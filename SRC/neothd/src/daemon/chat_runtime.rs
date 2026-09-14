//! Daemon-owned execution for the sealed plain chat RPC.
//!
//! The caller has already passed same-user authentication and parsed the
//! sealed request.  This runtime deliberately owns the remaining lifetime:
//! admission, one accepted configuration snapshot, durable consent, the
//! daemon provider and writer, response construction, and shutdown drain.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

use crate::cli::chat_turn_pipeline::{
    self, ChatOutput, ChatTurnEvent, ChatTurnEventSink, ChatTurnTerminal,
};
use crate::config::reload::{AcceptedConfigSnapshot, ReloadController};
use crate::daemon::audit_rpc::{
    CHAT_TURN_RESPONSE_TIMEOUT, DAEMON_PLAIN_CHAT_MAX_RECORDS,
    DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES, DaemonPlainChatRecord, DaemonPlainChatRecordKind,
    DaemonPlainChatRequest, DaemonPlainChatResponse, DaemonPlainChatTerminal,
    validate_daemon_plain_chat_request, validate_daemon_plain_chat_response,
};
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

/// The runtime is constructed before the audit-RPC listener is made
/// discoverable. Provider creation stays in `run_serve`; until it publishes
/// the existing shared provider, requests receive an unavailable response.
pub(crate) struct DaemonChatRuntime {
    selected_home: PathBuf,
    selected_config_path: PathBuf,
    active_segment_path: PathBuf,
    reload_controller: Arc<ReloadController>,
    writer: WalWriterHandle,
    // This state is intentionally synchronous: the active-operation guard
    // must release it from `Drop` when its connection future is cancelled.
    state: std::sync::Mutex<RuntimeState>,
    changed: Notify,
}

struct RuntimeState {
    accepting: bool,
    provider: Option<PublishedProvider>,
    active: Option<ActiveTurn>,
    next_turn_id: u64,
}

struct PublishedProvider {
    provider: Arc<dyn Provider>,
    accepted_epoch: u64,
}

struct ActiveTurn {
    id: u64,
    cancellation: chat_turn_pipeline::ChatTurnCancellation,
}

struct Admission {
    id: u64,
    provider: Arc<dyn Provider>,
    accepted: Arc<AcceptedConfigSnapshot>,
    cancellation: chat_turn_pipeline::ChatTurnCancellation,
}

/// Owns one admitted slot for the complete connection future. Dropping the
/// future (including a listener JoinSet abort) cannot strand shutdown behind a
/// stale `active` record because this guard clears and notifies synchronously.
struct ActiveOperationGuard<'a> {
    runtime: &'a DaemonChatRuntime,
    id: u64,
}

impl Drop for ActiveOperationGuard<'_> {
    fn drop(&mut self) {
        self.runtime.finish_sync(self.id);
    }
}

const CHAT_TURN_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
enum AdmissionError {
    Closing,
    Busy,
    ProviderUnavailable,
    ProviderConfigChanged,
}

impl DaemonChatRuntime {
    pub(crate) fn new(
        selected_home: PathBuf,
        selected_config_path: PathBuf,
        active_segment_path: PathBuf,
        reload_controller: Arc<ReloadController>,
        writer: WalWriterHandle,
    ) -> Self {
        Self {
            selected_home,
            selected_config_path,
            active_segment_path,
            reload_controller,
            writer,
            state: std::sync::Mutex::new(RuntimeState {
                accepting: true,
                provider: None,
                active: None,
                next_turn_id: 0,
            }),
            changed: Notify::new(),
        }
    }

    /// Publish exactly the provider already constructed by `run_serve`.
    /// There is intentionally no factory, reload, or fallback creation here.
    pub(crate) async fn publish_provider(
        &self,
        provider: Arc<dyn Provider>,
        accepted_epoch: u64,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        anyhow::ensure!(
            state.provider.is_none(),
            "daemon chat provider already published"
        );
        state.provider = Some(PublishedProvider {
            provider,
            accepted_epoch,
        });
        Ok(())
    }

    /// Stop new admissions, cancel the one admitted operation, and wait for
    /// the operation which owns its stream and response write to settle.  The
    /// daemon writer deliberately remains open; `run_serve` performs its one
    /// global drain only after this returns and all runtime roots are dropped.
    pub(crate) async fn close_and_drain(&self) {
        let cancellation = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.accepting = false;
            state
                .active
                .as_ref()
                .map(|active| active.cancellation.clone())
        };
        if let Some(cancellation) = cancellation {
            cancellation.close();
        }
        loop {
            let notified = self.changed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .active
                .is_none()
            {
                return;
            }
            notified.await;
        }
    }

    /// Execute and write exactly one authenticated sealed request.  No task is
    /// detached: the accepting connection awaits this future, and shutdown
    /// waits for it through `close_and_drain` before it permits global WAL
    /// closure.
    pub(crate) async fn handle_authenticated_turn(
        &self,
        mut stream: crate::daemon::audit_rpc::AuditStream,
        request: DaemonPlainChatRequest,
    ) -> Result<()> {
        // The audit-RPC server validates before dispatch. Keep the same sealed
        // request boundary here so a direct caller cannot admit a command,
        // reach consent/config preparation, invoke the provider, or append WAL.
        validate_request(&request)?;
        let admission = match self.admit().await {
            Ok(admission) => admission,
            Err(AdmissionError::Closing) => {
                write_failure_with_deadline(&mut stream, 503, "daemon chat is shutting down")
                    .await?;
                return Ok(());
            }
            Err(AdmissionError::Busy) => {
                write_failure_with_deadline(&mut stream, 429, "daemon chat is busy").await?;
                return Ok(());
            }
            Err(AdmissionError::ProviderUnavailable) => {
                write_failure_with_deadline(
                    &mut stream,
                    503,
                    "daemon chat provider is unavailable",
                )
                .await?;
                return Ok(());
            }
            Err(AdmissionError::ProviderConfigChanged) => {
                write_failure_with_deadline(
                    &mut stream,
                    503,
                    "daemon chat provider is not compatible with the accepted configuration",
                )
                .await?;
                return Ok(());
            }
        };
        let _active = ActiveOperationGuard {
            runtime: self,
            id: admission.id,
        };

        // Close the gate before the deadline branch releases the owned engine
        // future.  There is no spawned provider task to outlive this scope;
        // dropping the future is cancellation of this connection-owned turn,
        // never evidence that a remote provider completed or was reverted.
        let turn_result = {
            let operation = self.execute_turn(
                request,
                Arc::clone(&admission.provider),
                Arc::clone(&admission.accepted),
                admission.cancellation.clone(),
            );
            tokio::pin!(operation);
            tokio::select! {
                result = &mut operation => Ok(result),
                _ = tokio::time::sleep(CHAT_TURN_RESPONSE_TIMEOUT) => {
                    admission.cancellation.close();
                    Err(())
                }
            }
        };
        match turn_result {
            Ok(Ok(response)) => write_with_deadline(&mut stream, response).await,
            Ok(Err(error)) => {
                match write_failure_with_deadline(&mut stream, 500, "daemon chat turn failed").await
                {
                    Ok(()) => Err(error),
                    Err(write_error) => {
                        Err(error
                            .context(format!("write daemon chat failure response: {write_error}")))
                    }
                }
            }
            Err(()) => {
                match write_failure_with_deadline(&mut stream, 503, "daemon chat turn timed out")
                    .await
                {
                    Ok(()) => Err(anyhow::anyhow!(
                        "daemon chat turn exceeded response deadline"
                    )),
                    Err(write_error) => Err(anyhow::anyhow!(
                        "daemon chat turn exceeded response deadline; timeout response write failed: {write_error}"
                    )),
                }
            }
        }
    }

    async fn admit(&self) -> std::result::Result<Admission, AdmissionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !state.accepting {
            return Err(AdmissionError::Closing);
        }
        if state.active.is_some() {
            return Err(AdmissionError::Busy);
        }
        let Some(published) = state.provider.as_ref() else {
            return Err(AdmissionError::ProviderUnavailable);
        };
        let accepted = self.reload_controller.accepted_snapshot();
        if accepted.epoch() != published.accepted_epoch {
            return Err(AdmissionError::ProviderConfigChanged);
        }
        let provider = Arc::clone(&published.provider);
        let id = state.next_turn_id;
        state.next_turn_id = state.next_turn_id.wrapping_add(1);
        let cancellation = chat_turn_pipeline::ChatTurnCancellation::default();
        state.active = Some(ActiveTurn {
            id,
            cancellation: cancellation.clone(),
        });
        Ok(Admission {
            id,
            provider,
            accepted,
            cancellation,
        })
    }

    fn finish_sync(&self, id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.active.as_ref().is_some_and(|active| active.id == id) {
            state.active = None;
            self.changed.notify_waiters();
        }
    }

    async fn execute_turn(
        &self,
        request: DaemonPlainChatRequest,
        provider: Arc<dyn Provider>,
        accepted: Arc<AcceptedConfigSnapshot>,
        cancellation: chat_turn_pipeline::ChatTurnCancellation,
    ) -> Result<DaemonPlainChatResponse> {
        validate_request(&request)?;
        let config = accepted.config();
        crate::consent::ensure_all_still_granted(&self.selected_home, config.as_ref())
            .context("recheck durable consent for daemon chat turn")?;

        let mut sink = PlainChatSink::default();
        let prepared = crate::cli::chat::prepare_daemon_plain_chat_turn(
            request.message,
            (*config).clone(),
            self.selected_config_path.clone(),
            self.selected_home.clone(),
            provider.as_ref(),
            cancellation.clone(),
            &mut sink,
        )
        .await?;
        let chat_turn_pipeline::ChatPreparationOutcome::Ready(mut prepared) = prepared else {
            anyhow::bail!("daemon plain chat unexpectedly completed during preparation");
        };
        let engine_result = chat_turn_pipeline::run_prepared_chat_turn(
            &mut prepared,
            provider.as_ref(),
            &self.writer,
            &self.active_segment_path,
            &mut sink,
        )
        .await;
        cancellation.close();
        let deferred = engine_result?;
        if let Some(output) = deferred {
            sink.accept_output(output)?;
        }
        let terminal = prepared
            .deferred_terminal
            .take()
            .context("daemon plain chat engine returned without a success terminal")?;
        let response = DaemonPlainChatResponse {
            records: sink.records,
            terminal: terminal.into(),
        };
        let encoded = serde_json::to_vec(&response).context("serialize daemon chat response")?;
        validate_daemon_plain_chat_response(&response, encoded.len())
            .map_err(anyhow::Error::msg)
            .context("validate daemon chat response bounds")?;
        Ok(response)
    }
}

#[derive(Default)]
struct PlainChatSink {
    records: Vec<DaemonPlainChatRecord>,
}

impl PlainChatSink {
    fn accept_output(&mut self, output: ChatOutput) -> Result<()> {
        let (kind, text) = match output {
            ChatOutput::HumanStdout { text } => (DaemonPlainChatRecordKind::Stdout, text),
            ChatOutput::HumanStderr { text } => (DaemonPlainChatRecordKind::Stderr, text),
            ChatOutput::Notice {
                stream: false,
                text,
            } => (DaemonPlainChatRecordKind::Notice, text),
            _ => anyhow::bail!("daemon plain chat received a streaming or control output"),
        };
        anyhow::ensure!(
            self.records.len() < DAEMON_PLAIN_CHAT_MAX_RECORDS,
            "daemon chat produced too many records"
        );
        anyhow::ensure!(
            text.len() <= DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES,
            "daemon chat record exceeds its response cap"
        );
        self.records.push(DaemonPlainChatRecord { kind, text });
        Ok(())
    }
}

impl ChatTurnEventSink for PlainChatSink {
    fn emit(&mut self, event: ChatTurnEvent) -> Result<()> {
        match event {
            ChatTurnEvent::Output(output) => self.accept_output(output),
            ChatTurnEvent::Terminal(_) => {
                anyhow::bail!("engine emitted daemon terminal before caller response boundary")
            }
        }
    }
}

impl From<ChatTurnTerminal> for DaemonPlainChatTerminal {
    fn from(value: ChatTurnTerminal) -> Self {
        match value {
            ChatTurnTerminal::Complete {
                provider,
                model,
                session_id,
            } => Self {
                provider,
                model,
                session_id,
            },
        }
    }
}

fn validate_request(request: &DaemonPlainChatRequest) -> Result<()> {
    validate_daemon_plain_chat_request(request)
        .map_err(anyhow::Error::msg)
        .context("validate daemon chat request bounds")?;
    Ok(())
}

async fn write_success(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
    response: DaemonPlainChatResponse,
) -> Result<()> {
    let body = serde_json::to_vec(&response).context("serialize daemon chat success response")?;
    validate_daemon_plain_chat_response(&response, body.len())
        .map_err(anyhow::Error::msg)
        .context("validate daemon chat success response bounds")?;
    write_http_json(stream, 200, &body).await
}

async fn write_with_deadline(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
    response: DaemonPlainChatResponse,
) -> Result<()> {
    tokio::time::timeout(CHAT_TURN_WRITE_TIMEOUT, write_success(stream, response))
        .await
        .map_err(|_| anyhow::anyhow!("daemon chat success response write exceeded deadline"))?
}

async fn write_failure(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
    status: u16,
    message: &str,
) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({ "error": message }))
        .context("serialize daemon chat failure response")?;
    write_http_json(stream, status, &body).await
}

async fn write_failure_with_deadline(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
    status: u16,
    message: &str,
) -> Result<()> {
    tokio::time::timeout(
        CHAT_TURN_WRITE_TIMEOUT,
        write_failure(stream, status, message),
    )
    .await
    .map_err(|_| anyhow::anyhow!("daemon chat failure response write exceeded deadline"))?
}

async fn write_http_json(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
    status: u16,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .context("write daemon chat response header")?;
    stream
        .write_all(body)
        .await
        .context("write daemon chat response body")?;
    stream
        .shutdown()
        .await
        .context("close daemon chat response stream")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::providers::{Completion, CompletionIdentity, Request};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct RuntimeProvider {
        calls: AtomicUsize,
        reply: String,
    }

    impl Default for RuntimeProvider {
        fn default() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                reply: "daemon runtime reply".into(),
            }
        }
    }

    #[async_trait]
    impl Provider for RuntimeProvider {
        fn name(&self) -> &'static str {
            "claude_cli"
        }

        fn default_model(&self) -> Option<&str> {
            Some("runtime-test-model")
        }

        async fn complete(&self, _request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                termination: Default::default(),
                text: self.reply.clone(),
                identity: CompletionIdentity {
                    provider: self.name().into(),
                    wire_model: "runtime-test-model".into(),
                    dispatch_route: Vec::new(),
                },
                model: "runtime-test-model".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(3),
                output_tokens: Some(2),
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    async fn test_runtime(
        grant_consent: bool,
        published_epoch: u64,
    ) -> (
        Arc<DaemonChatRuntime>,
        Arc<RuntimeProvider>,
        tempfile::TempDir,
        WalWriterHandle,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        test_runtime_with_reply(
            grant_consent,
            published_epoch,
            "daemon runtime reply".into(),
        )
        .await
    }

    async fn test_runtime_with_reply(
        grant_consent: bool,
        published_epoch: u64,
        reply: String,
    ) -> (
        Arc<DaemonChatRuntime>,
        Arc<RuntimeProvider>,
        tempfile::TempDir,
        WalWriterHandle,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        let home = tempfile::tempdir().expect("create daemon runtime test home");
        if grant_consent {
            crate::consent::grant(home.path(), ProviderKind::ClaudeCli)
                .expect("grant durable daemon test consent");
        }
        let mut config = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_model: Some("runtime-test-model".into()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("serialize test config"),
        )
        .expect("write daemon runtime test config");
        let wal = crate::cli::serve_tasks::prepare_wal(home.path(), None)
            .await
            .expect("open one daemon-owned WAL writer");
        let controller = Arc::new(ReloadController::new(config, config_path.clone()));
        let runtime = Arc::new(DaemonChatRuntime::new(
            home.path().to_path_buf(),
            config_path,
            wal.segment_path.clone(),
            Arc::clone(&controller),
            wal.writer.clone(),
        ));
        let provider = Arc::new(RuntimeProvider {
            calls: AtomicUsize::new(0),
            reply,
        });
        runtime
            .publish_provider(Arc::clone(&provider) as Arc<dyn Provider>, published_epoch)
            .await
            .expect("publish fixture provider");
        let writer_join = wal.writer_join;
        (runtime, provider, home, wal.writer, writer_join)
    }

    async fn execute_admitted_turn(
        runtime: &DaemonChatRuntime,
        message: &str,
    ) -> Result<DaemonPlainChatResponse> {
        let admission = runtime
            .admit()
            .await
            .map_err(|_| anyhow::anyhow!("admit fixture turn"))?;
        let result = runtime
            .execute_turn(
                DaemonPlainChatRequest {
                    schema_version: crate::daemon::audit_rpc::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
                    message: message.into(),
                },
                admission.provider,
                admission.accepted,
                admission.cancellation,
            )
            .await;
        runtime.finish_sync(admission.id);
        result
    }

    #[tokio::test]
    async fn two_real_daemon_turns_share_the_live_global_writer() {
        let (runtime, provider, _home, writer, writer_join) = test_runtime(true, 0).await;
        let first = execute_admitted_turn(&runtime, "first daemon turn")
            .await
            .expect("first daemon turn");
        let second = execute_admitted_turn(&runtime, "second daemon turn")
            .await
            .expect("second daemon turn on the same writer");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(first.terminal.provider, "claude_cli");
        assert_eq!(second.terminal.model, "runtime-test-model");
        assert!(
            first
                .records
                .iter()
                .any(|record| record.text.contains("daemon runtime reply"))
        );
        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join daemon writer task")
            .expect("daemon writer succeeds");
    }

    #[tokio::test]
    async fn missing_consent_and_provider_epoch_mismatch_start_no_provider_call() {
        let (runtime, provider, _home, writer, writer_join) = test_runtime(false, 0).await;
        assert!(
            execute_admitted_turn(&runtime, "missing consent")
                .await
                .is_err()
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join missing-consent writer")
            .expect("writer succeeds");

        let (runtime, provider, _home, writer, writer_join) = test_runtime(true, 1).await;
        assert!(matches!(
            runtime.admit().await,
            Err(AdmissionError::ProviderConfigChanged)
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join epoch-mismatch writer")
            .expect("writer succeeds");
    }

    #[tokio::test]
    async fn direct_authenticated_slash_requests_reject_before_provider_config_or_wal_effects() {
        let (runtime, provider, home, writer, writer_join) = test_runtime(true, 0).await;
        let config_path = home.path().join("freedom.yaml");
        let config_before = std::fs::read(&config_path).expect("read daemon test config baseline");
        let segment_path = home.path().join("wal").join("000001.wal");
        let wal_len_before = std::fs::metadata(&segment_path)
            .expect("read daemon WAL baseline")
            .len();

        for command in ["/skill disable academic_research", " \t/background worker"] {
            let (_peer, server) = tokio::io::duplex(1);
            assert!(
                runtime
                    .handle_authenticated_turn(
                        Box::new(server),
                        DaemonPlainChatRequest {
                            schema_version:
                                crate::daemon::audit_rpc::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
                            message: command.into(),
                        },
                    )
                    .await
                    .is_err(),
                "direct authenticated command body must be refused before turn admission: {command:?}"
            );
        }

        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            0,
            "slash requests invoke no provider"
        );
        assert_eq!(
            std::fs::read(&config_path).expect("read daemon test config after slash rejection"),
            config_before,
            "slash requests do not mutate selected configuration"
        );
        assert_eq!(
            std::fs::metadata(&segment_path)
                .expect("read daemon WAL after slash rejection")
                .len(),
            wal_len_before,
            "slash requests append no daemon WAL record"
        );

        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join slash-rejection writer")
            .expect("slash-rejection writer succeeds");
    }
    #[tokio::test]
    async fn capacity_rejects_a_second_turn_and_shutdown_waits_for_the_cancelled_owner() {
        let (runtime, provider, _home, writer, writer_join) = test_runtime(true, 0).await;
        let active = runtime
            .admit()
            .await
            .expect("admit first capacity-one turn");
        assert!(matches!(runtime.admit().await, Err(AdmissionError::Busy)));
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            0,
            "busy admission starts no provider"
        );

        let draining_runtime = Arc::clone(&runtime);
        let draining = tokio::spawn(async move { draining_runtime.close_and_drain().await });
        tokio::task::yield_now().await;
        assert!(
            active.cancellation.check_open("shutdown test").is_err(),
            "shutdown must close the active turn before it can publish success"
        );
        assert!(
            !draining.is_finished(),
            "shutdown waits for the owning turn to settle"
        );
        runtime.finish_sync(active.id);
        draining.await.expect("shutdown drain joins active owner");
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join capacity writer")
            .expect("capacity writer succeeds");
    }

    #[test]
    fn plain_sink_enforces_typed_record_count_and_rejects_stream_control() {
        let mut sink = PlainChatSink::default();
        for _ in 0..DAEMON_PLAIN_CHAT_MAX_RECORDS {
            sink.accept_output(ChatOutput::HumanStdout { text: "ok".into() })
                .expect("bounded plain output");
        }
        assert!(
            sink.accept_output(ChatOutput::HumanStdout {
                text: "overflow".into()
            })
            .is_err()
        );
        assert!(
            sink.accept_output(ChatOutput::ProviderDelta {
                sequence: 1,
                text: "forbidden".into(),
                stream_control_token: None,
            })
            .is_err()
        );
    }

    async fn wait_for_provider_call(provider: &RuntimeProvider) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.calls.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated fixture turn reaches the provider");
    }

    #[tokio::test]
    async fn authenticated_stalled_peer_releases_shutdown_after_bounded_owned_write() {
        let (runtime, provider, _home, writer, writer_join) =
            test_runtime_with_reply(true, 0, "x".repeat(60 * 1024)).await;
        let (_non_reading_peer, server) = tokio::io::duplex(1);
        let connection_runtime = Arc::clone(&runtime);
        let connection = tokio::spawn(async move {
            connection_runtime
                .handle_authenticated_turn(
                    Box::new(server),
                    DaemonPlainChatRequest {
                        schema_version: crate::daemon::audit_rpc::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
                        message: "stalled response".into(),
                    },
                )
                .await
        });

        wait_for_provider_call(&provider).await;
        tokio::time::timeout(
            CHAT_TURN_WRITE_TIMEOUT + Duration::from_secs(1),
            runtime.close_and_drain(),
        )
        .await
        .expect("shutdown waits only for the connection-owned bounded write");
        let result = connection.await.expect("join stalled connection owner");
        assert!(
            result.is_err(),
            "a backpressured peer receives no completed success terminal"
        );

        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join stalled-peer writer")
            .expect("stalled-peer writer succeeds");
    }

    #[tokio::test]
    async fn cancelled_authenticated_connection_releases_active_slot_before_shutdown_drain() {
        let (runtime, provider, _home, writer, writer_join) = test_runtime(true, 0).await;
        let (_non_reading_peer, server) = tokio::io::duplex(1);
        let connection_runtime = Arc::clone(&runtime);
        let connection = tokio::spawn(async move {
            connection_runtime
                .handle_authenticated_turn(
                    Box::new(server),
                    DaemonPlainChatRequest {
                        schema_version: crate::daemon::audit_rpc::DAEMON_PLAIN_CHAT_SCHEMA_VERSION,
                        message: "cancel owned connection".into(),
                    },
                )
                .await
        });

        wait_for_provider_call(&provider).await;
        connection.abort();
        assert!(
            connection
                .await
                .expect_err("listener cancellation aborts connection future")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.close_and_drain())
            .await
            .expect("cancelled connection guard releases runtime shutdown drain");

        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join cancellation writer")
            .expect("cancellation writer succeeds");
    }
}
