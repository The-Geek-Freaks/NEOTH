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
    DAEMON_PLAIN_CHAT_MAX_RECORDS, DAEMON_PLAIN_CHAT_RESPONSE_MAX_BYTES, DaemonPlainChatErrorCode,
    DaemonPlainChatErrorResponse, DaemonPlainChatRecord, DaemonPlainChatRecordKind,
    DaemonPlainChatRequest, DaemonPlainChatResponse, DaemonPlainChatResponseFeedbackTarget,
    DaemonPlainChatTerminal, validate_daemon_plain_chat_error_response,
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

/// Content-free identity of the authority accepted for a GUI effect.  The GUI
/// owner stores this with Intent and compares it again at the concrete start
/// boundary; it never reconstructs a provider from configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuiEffectAuthority {
    pub(crate) config_epoch: u64,
    pub(crate) provider_identity: String,
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

    /// The GUI registry binds its sealed descriptor to this exact accepted
    /// epoch. It exposes neither configuration bytes nor a reload authority.
    pub(crate) fn accepted_config_epoch(&self) -> Result<u64> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let published = state
            .provider
            .as_ref()
            .context("daemon chat provider is unavailable")?;
        let accepted = self.reload_controller.accepted_snapshot();
        anyhow::ensure!(
            accepted.epoch() == published.accepted_epoch,
            "daemon chat provider epoch changed"
        );
        Ok(published.accepted_epoch)
    }

    /// Concrete W41 start boundary recheck using the already-published W39
    /// provider/home/epoch authority. It intentionally has no factory path.
    pub(crate) fn recheck_gui_effect_authority(&self) -> Result<GuiEffectAuthority> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let published = state
            .provider
            .as_ref()
            .context("daemon chat provider is unavailable")?;
        let accepted = self.reload_controller.accepted_snapshot();
        anyhow::ensure!(
            accepted.epoch() == published.accepted_epoch,
            "daemon chat provider epoch changed"
        );
        Ok(GuiEffectAuthority {
            config_epoch: published.accepted_epoch,
            provider_identity: published.provider.name().to_owned(),
        })
    }

    /// Content-free W41 lifecycle ACK. This is intentionally owned beside the
    /// shared writer: GUI transport cannot create a second WAL owner or accept
    /// a terminal ahead of its durable receipt.
    pub(crate) async fn append_gui_lifecycle(&self, payload: Vec<u8>) -> Result<()> {
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                .event_subtype(crate::wal::events::ExtendedSubtype::GuiChatLifecycle as u8)
                .build();
        self.writer
            .append(header, payload)
            .await
            .context("append GUI chat lifecycle WAL record")
            .map(|_| ())
    }

    /// Execute the W41 GUI producer using the exact W39 provider permit,
    /// accepted config snapshot, writer and segment. The GUI runtime owns
    /// tickets/replay/ledger; this core accepts only daemon-staged paths.
    #[allow(clippy::too_many_arguments)] // Keeps typed W41 producer boundary explicit.
    pub(crate) async fn execute_gui_stream_turn(
        &self,
        message: String,
        model: Option<String>,
        skill: Option<String>,
        admitted_session_id: Option<String>,
        incognito: bool,
        reasoning_display: bool,
        staged_attachments: Vec<PathBuf>,
        ephemeral_consent: crate::consent::EphemeralConsent,
        cancellation: chat_turn_pipeline::ChatTurnCancellation,
        sink: &mut dyn ChatTurnEventSink,
        effect_gate: Option<Arc<dyn crate::providers::ChatTurnEffectGate>>,
    ) -> Result<ChatTurnTerminal> {
        let admission = self
            .admit_with_cancellation(cancellation.clone())
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "GUI admission failed: {}",
                    match error {
                        AdmissionError::Closing => "closing",
                        AdmissionError::Busy => "busy",
                        AdmissionError::ProviderUnavailable => "provider unavailable",
                        AdmissionError::ProviderConfigChanged => "provider epoch changed",
                    }
                )
            })?;
        let _active = ActiveOperationGuard {
            runtime: self,
            id: admission.id,
        };
        let config = admission.accepted.config();
        // Do not perform a whole-config durable-consent rejection here. An
        // AllowOnce capability deliberately has no durable marker. The exact
        // leaf authorizer consumes/rechecks that one-shot route immediately
        // before its real transport start, after the W41 authority recheck.
        let prepared = crate::cli::chat::prepare_daemon_gui_chat_turn(
            message,
            model,
            skill,
            admitted_session_id,
            incognito,
            reasoning_display,
            staged_attachments,
            ephemeral_consent,
            (*config).clone(),
            self.selected_config_path.clone(),
            self.selected_home.clone(),
            admission.provider.as_ref(),
            Arc::clone(&self.reload_controller),
            cancellation.clone(),
            sink,
        )
        .await?;
        let chat_turn_pipeline::ChatPreparationOutcome::Ready(mut prepared) = prepared else {
            anyhow::bail!("daemon GUI chat completed before provider admission")
        };
        let deferred = chat_turn_pipeline::run_prepared_chat_turn_with_effect_gate(
            &mut prepared,
            admission.provider.as_ref(),
            &self.writer,
            &self.active_segment_path,
            sink,
            effect_gate,
        )
        .await?;
        cancellation.close();
        if let Some(output) = deferred {
            sink.emit(ChatTurnEvent::Output(output))?;
        }
        let mut terminal = prepared
            .deferred_terminal
            .take()
            .context("daemon GUI chat engine returned without terminal")?;
        let feedback_eligible_agent_receipt = prepared.take_feedback_eligible_agent_receipt();
        self.attach_response_feedback_after_flush(
            &mut terminal,
            incognito,
            feedback_eligible_agent_receipt.as_ref(),
        )
        .await;
        Ok(terminal)
    }

    /// Register one non-incognito terminal response only after a FIFO durability
    /// barrier ACKs every earlier write from this daemon-owned turn. The barrier
    /// keeps the long-lived writer open; a failure leaves the completed terminal
    /// truthful but unavailable for response feedback.
    async fn attach_response_feedback_after_flush(
        &self,
        terminal: &mut ChatTurnTerminal,
        incognito: bool,
        feedback_eligible_agent_receipt: Option<
            &crate::memory::transcript_store::CommittedAgentTurnReceipt,
        >,
    ) {
        if terminal.response_feedback_target().is_some() || terminal.response_feedback_unavailable()
        {
            return;
        }
        if incognito {
            terminal.mark_response_feedback_unavailable();
            return;
        }
        let Some(feedback_eligible_agent_receipt) = feedback_eligible_agent_receipt else {
            terminal.mark_response_feedback_unavailable();
            return;
        };
        let session_id = match terminal {
            ChatTurnTerminal::Complete { session_id, .. } => session_id.clone(),
        };
        let Some(session_id) = session_id.filter(|session_id| !session_id.is_empty()) else {
            terminal.mark_response_feedback_unavailable();
            return;
        };
        if self.writer.flush_pending().await.is_err() {
            terminal.mark_response_feedback_unavailable();
            return;
        }
        match crate::feedback::response::register_drained_terminal_response_bound(
            &self.selected_home,
            &session_id,
            false,
            crate::time::now_unix_i64(),
            feedback_eligible_agent_receipt,
        ) {
            Ok(Some(status)) => {
                terminal.set_response_feedback_target(chat_turn_pipeline::ResponseFeedbackTarget {
                    response_id: status.response_id.as_str().to_owned(),
                    session_id: status.session_id,
                    revision: status.revision,
                })
            }
            Ok(None) | Err(_) => terminal.mark_response_feedback_unavailable(),
        }
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

        // The shared turn pipeline owns the only meaningful-progress timeout.
        // An outer equally-timed daemon deadline would race its typed outcome
        // and could misreport the provider attempt as a generic transport
        // failure.
        let turn_result = self
            .execute_turn(
                request,
                Arc::clone(&admission.provider),
                Arc::clone(&admission.accepted),
                admission.cancellation.clone(),
            )
            .await;
        match turn_result {
            Ok(response) => write_with_deadline(&mut stream, response).await,
            Err(error) => {
                if error
                    .downcast_ref::<crate::cli::chat_turn_watchdog::TurnSilenceTimeout>()
                    .is_some()
                {
                    return match write_turn_silence_timeout_with_deadline(&mut stream).await {
                        Ok(()) => Err(error),
                        Err(write_error) => Err(error.context(format!(
                            "write daemon chat silence-timeout response: {write_error}"
                        ))),
                    };
                }
                match write_failure_with_deadline(&mut stream, 500, "daemon chat turn failed").await
                {
                    Ok(()) => Err(error),
                    Err(write_error) => {
                        Err(error
                            .context(format!("write daemon chat failure response: {write_error}")))
                    }
                }
            }
        }
    }

    async fn admit(&self) -> std::result::Result<Admission, AdmissionError> {
        self.admit_with_cancellation(chat_turn_pipeline::ChatTurnCancellation::default())
            .await
    }

    async fn admit_with_cancellation(
        &self,
        cancellation: chat_turn_pipeline::ChatTurnCancellation,
    ) -> std::result::Result<Admission, AdmissionError> {
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
            Arc::clone(&self.reload_controller),
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
        let mut terminal = prepared
            .deferred_terminal
            .take()
            .context("daemon plain chat engine returned without a success terminal")?;
        let feedback_eligible_agent_receipt = prepared.take_feedback_eligible_agent_receipt();
        self.attach_response_feedback_after_flush(
            &mut terminal,
            false,
            feedback_eligible_agent_receipt.as_ref(),
        )
        .await;
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
            // W167's content-free typed companion is reserved for the daemon
            // GUI stream. The sealed plain response has no recall-chip field
            // and must neither serialize nor reconstruct it.
            ChatOutput::RecallChipBatch { .. } => return Ok(()),
            // W168's typed live state is likewise private to the daemon GUI
            // stream and has no sealed plain-RPC representation.
            ChatOutput::LiveThroughputState { .. } => return Ok(()),
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
                response_feedback,
                response_feedback_unavailable,
            } => Self {
                provider,
                model,
                session_id,
                response_feedback: response_feedback.map(|target| {
                    DaemonPlainChatResponseFeedbackTarget {
                        response_id: target.response_id,
                        session_id: target.session_id,
                        revision: target.revision,
                    }
                }),
                response_feedback_unavailable,
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

async fn write_turn_silence_timeout_with_deadline(
    stream: &mut crate::daemon::audit_rpc::AuditStream,
) -> Result<()> {
    let body = DaemonPlainChatErrorResponse {
        code: DaemonPlainChatErrorCode::TurnSilenceTimeout,
        timeout_seconds: crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT.as_secs(),
        retryable: true,
    };
    validate_daemon_plain_chat_error_response(&body)
        .map_err(anyhow::Error::msg)
        .context("validate daemon chat silence-timeout response")?;
    let body =
        serde_json::to_vec(&body).context("serialize daemon chat silence-timeout response")?;
    tokio::time::timeout(CHAT_TURN_WRITE_TIMEOUT, write_http_json(stream, 503, &body))
        .await
        .map_err(|_| {
            anyhow::anyhow!("daemon chat silence-timeout response write exceeded deadline")
        })?
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

    struct DiscardingGuiSink;

    impl ChatTurnEventSink for DiscardingGuiSink {
        fn emit(&mut self, _event: ChatTurnEvent) -> Result<()> {
            Ok(())
        }
    }

    async fn execute_gui_turn(
        runtime: &DaemonChatRuntime,
        message: String,
        incognito: bool,
    ) -> Result<ChatTurnTerminal> {
        execute_gui_turn_with_admitted_session(runtime, message, None, incognito).await
    }

    async fn execute_gui_turn_with_admitted_session(
        runtime: &DaemonChatRuntime,
        message: String,
        admitted_session_id: Option<String>,
        incognito: bool,
    ) -> Result<ChatTurnTerminal> {
        let mut sink = DiscardingGuiSink;
        runtime
            .execute_gui_stream_turn(
                message,
                None,
                None,
                admitted_session_id,
                incognito,
                false,
                Vec::new(),
                crate::consent::EphemeralConsent::default(),
                chat_turn_pipeline::ChatTurnCancellation::default(),
                &mut sink,
                None,
            )
            .await
    }

    #[tokio::test]
    async fn w703_admitted_gui_session_scopes_real_transcript_and_isolates_incognito() {
        let (runtime, provider, home, writer, writer_join) =
            test_runtime_with_reply(true, 0, "W703 assistant reply".into()).await;
        let session_a = "w703-browser-session-a";
        let session_b = "w703-browser-session-b";
        let incognito_session = "w703-browser-incognito";

        execute_gui_turn_with_admitted_session(
            &runtime,
            "W703 operator prompt A".into(),
            Some(session_a.into()),
            false,
        )
        .await
        .expect("persist real GUI turn in admitted browser session A");
        execute_gui_turn_with_admitted_session(
            &runtime,
            "W703 operator prompt B".into(),
            Some(session_b.into()),
            false,
        )
        .await
        .expect("persist real GUI turn in admitted browser session B");
        execute_gui_turn_with_admitted_session(
            &runtime,
            "W703 incognito operator prompt".into(),
            Some(incognito_session.into()),
            true,
        )
        .await
        .expect("complete incognito GUI turn without transcript persistence");

        let transcript_path = home.path().join("views.db");
        let session_a_rows = crate::memory::transcript_store::read_session_turns_at(
            &transcript_path,
            session_a,
        )
        .expect("read actual transcript for admitted browser session A");
        assert_eq!(
            session_a_rows
                .iter()
                .map(|row| (row.role.as_str(), row.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("operator", "W703 operator prompt A"),
                ("agent", "W703 assistant reply"),
            ],
            "the real producer writes both transcript rows under session A"
        );
        let session_b_rows = crate::memory::transcript_store::read_session_turns_at(
            &transcript_path,
            session_b,
        )
        .expect("read actual transcript for admitted browser session B");
        assert_eq!(
            session_b_rows
                .iter()
                .map(|row| (row.role.as_str(), row.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("operator", "W703 operator prompt B"),
                ("agent", "W703 assistant reply"),
            ],
            "separate admitted browser sessions never share transcript rows"
        );
        assert!(
            crate::memory::transcript_store::read_session_turns_at(
                &transcript_path,
                incognito_session,
            )
            .expect("read incognito browser session")
            .is_empty(),
            "incognito must neither persist nor join the browser session transcript"
        );
        let transcript_db = rusqlite::Connection::open_with_flags(
            &transcript_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("open actual transcript database read-only");
        let raw_turn_count: i64 = transcript_db
            .query_row("SELECT COUNT(*) FROM raw_turns", [], |row| row.get(0))
            .expect("count actual transcript rows");
        assert_eq!(
            raw_turn_count, 4,
            "only the two non-incognito real GUI turns persist transcript rows"
        );
        let incognito_rows: i64 = transcript_db
            .query_row(
                "SELECT COUNT(*) FROM raw_turns WHERE text = ?1",
                ["W703 incognito operator prompt"],
                |row| row.get(0),
            )
            .expect("query actual transcript for incognito prompt");
        assert_eq!(
            incognito_rows, 0,
            "incognito prompt never persists under a generated private identity"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);

        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join W703 daemon writer")
            .expect("W703 daemon writer succeeds");
    }

    #[tokio::test]
    async fn w177_daemon_gui_feedback_receipt_exports_only_redacted_accepted_pair() {
        let secret = "token=sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let (runtime, provider, home, writer, writer_join) =
            test_runtime_with_reply(true, 0, format!("W177 assistant reply {secret}")).await;

        let terminal = execute_gui_turn(&runtime, format!("W177 operator prompt {secret}"), false)
            .await
            .expect("execute real daemon GUI producer");
        let target = terminal
            .response_feedback_target()
            .cloned()
            .expect("flushed strict receipt issues an opaque feedback target");
        assert!(!terminal.response_feedback_unavailable());
        assert!(!target.response_id.contains(secret));
        assert!(!target.session_id.contains(secret));

        let response_id = crate::feedback::response::ResponseId::parse(&target.response_id)
            .expect("daemon terminal response id is valid");
        assert!(matches!(
            crate::feedback::response::apply_response_feedback(
                home.path(),
                &response_id,
                &target.session_id,
                target.revision,
                crate::feedback::response::ResponseFeedbackOperation::Set(
                    crate::feedback::response::ResponseSignal::Accepted,
                ),
                1_772_000_001,
            )
            .expect("accept daemon terminal feedback"),
            crate::feedback::response::ResponseFeedbackOutcome::Set { revision: 1, .. }
        ));

        let openai_path = home.path().join("w177-openai.jsonl");
        let openai_summary = crate::daemon::train_export::export_training_set(
            home.path(),
            &openai_path,
            crate::daemon::train_export::TrainingSetFormat::Openai,
        )
        .expect("export accepted OpenAI training pair");
        assert_eq!(openai_summary.exported, 1);
        let openai_text = std::fs::read_to_string(&openai_path).expect("read OpenAI export");
        let openai_lines: Vec<_> = openai_text.lines().collect();
        assert_eq!(openai_lines.len(), 1);
        let openai: serde_json::Value =
            serde_json::from_str(openai_lines[0]).expect("parse OpenAI export line");
        let messages = openai["messages"]
            .as_array()
            .expect("OpenAI export has messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"].as_str(), Some("user"));
        assert_eq!(messages[1]["role"].as_str(), Some("assistant"));
        assert!(openai_lines[0].contains("REDACTED"));
        assert!(!openai_lines[0].contains(secret));
        assert!(!openai_lines[0].contains("raw_turn"));
        assert!(!openai_lines[0].contains("session"));
        assert!(!openai_lines[0].contains(&target.response_id));
        assert!(!openai_lines[0].contains(&target.session_id));

        let sharegpt_path = home.path().join("w177-sharegpt.jsonl");
        let sharegpt_summary = crate::daemon::train_export::export_training_set(
            home.path(),
            &sharegpt_path,
            crate::daemon::train_export::TrainingSetFormat::Sharegpt,
        )
        .expect("export accepted ShareGPT training pair");
        assert_eq!(sharegpt_summary.exported, 1);
        let sharegpt_text = std::fs::read_to_string(&sharegpt_path).expect("read ShareGPT export");
        let sharegpt_lines: Vec<_> = sharegpt_text.lines().collect();
        assert_eq!(sharegpt_lines.len(), 1);
        let sharegpt: serde_json::Value =
            serde_json::from_str(sharegpt_lines[0]).expect("parse ShareGPT export line");
        let conversations = sharegpt["conversations"]
            .as_array()
            .expect("ShareGPT export has conversations");
        assert_eq!(conversations.len(), 2);
        assert_eq!(conversations[0]["from"].as_str(), Some("human"));
        assert_eq!(conversations[1]["from"].as_str(), Some("gpt"));
        assert!(sharegpt_lines[0].contains("REDACTED"));
        assert!(!sharegpt_lines[0].contains(secret));
        assert!(!sharegpt_lines[0].contains("raw_turn"));
        assert!(!sharegpt_lines[0].contains("session"));
        assert!(!sharegpt_lines[0].contains(&target.response_id));
        assert!(!sharegpt_lines[0].contains(&target.session_id));

        assert!(matches!(
            crate::feedback::response::apply_response_feedback(
                home.path(),
                &response_id,
                &target.session_id,
                1,
                crate::feedback::response::ResponseFeedbackOperation::Set(
                    crate::feedback::response::ResponseSignal::NeedsCorrection,
                ),
                1_772_000_002,
            )
            .expect("set needs-correction feedback"),
            crate::feedback::response::ResponseFeedbackOutcome::Replaced { revision: 2, .. }
        ));
        let needs_correction = crate::daemon::train_export::export_training_set(
            home.path(),
            &home.path().join("w177-needs-correction.jsonl"),
            crate::daemon::train_export::TrainingSetFormat::Openai,
        )
        .expect("export needs-correction exclusion");
        assert_eq!(needs_correction.exported, 0);
        assert_eq!(needs_correction.excluded_needs_correction, 1);

        assert!(matches!(
            crate::feedback::response::apply_response_feedback(
                home.path(),
                &response_id,
                &target.session_id,
                2,
                crate::feedback::response::ResponseFeedbackOperation::Set(
                    crate::feedback::response::ResponseSignal::NotHelpful,
                ),
                1_772_000_003,
            )
            .expect("set not-helpful feedback"),
            crate::feedback::response::ResponseFeedbackOutcome::Replaced { revision: 3, .. }
        ));
        let not_helpful = crate::daemon::train_export::export_training_set(
            home.path(),
            &home.path().join("w177-not-helpful.jsonl"),
            crate::daemon::train_export::TrainingSetFormat::Openai,
        )
        .expect("export not-helpful exclusion");
        assert_eq!(not_helpful.exported, 0);
        assert_eq!(not_helpful.excluded_not_helpful, 1);

        assert!(matches!(
            crate::feedback::response::apply_response_feedback(
                home.path(),
                &response_id,
                &target.session_id,
                3,
                crate::feedback::response::ResponseFeedbackOperation::Remove,
                1_772_000_004,
            )
            .expect("remove feedback"),
            crate::feedback::response::ResponseFeedbackOutcome::Removed { revision: 4 }
        ));
        let removed = crate::daemon::train_export::export_training_set(
            home.path(),
            &home.path().join("w177-removed.jsonl"),
            crate::daemon::train_export::TrainingSetFormat::Openai,
        )
        .expect("export removed-feedback exclusion");
        assert_eq!(removed.exported, 0);
        assert_eq!(removed.excluded_unlabelled, 1);

        let incognito = execute_gui_turn(&runtime, "W177 incognito producer".into(), true)
            .await
            .expect("complete incognito daemon GUI producer");
        assert!(incognito.response_feedback_target().is_none());
        assert!(incognito.response_feedback_unavailable());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);

        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join W177 daemon writer")
            .expect("W177 daemon writer succeeds");
    }

    #[tokio::test]
    async fn generic_gui_lifecycle_remains_unattributed_without_an_admitted_turn() {
        let (runtime, _provider, _home, writer, writer_join) = test_runtime(true, 0).await;
        let segment_path = runtime.active_segment_path.clone();
        runtime
            .append_gui_lifecycle(br#"{"phase":"queued"}"#.to_vec())
            .await
            .expect("append generic GUI lifecycle");
        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join generic GUI lifecycle writer")
            .expect("generic GUI lifecycle writer succeeds");

        let wal = std::fs::read(segment_path).expect("read generic GUI lifecycle WAL");
        let mut lifecycle_session_ids = Vec::new();
        crate::wal::scan::for_each_frame(&wal, |_, frame| {
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::GuiChatLifecycle as u8
            {
                lifecycle_session_ids.push(frame.header.session_id);
            }
            Ok(())
        })
        .expect("scan generic GUI lifecycle WAL");
        assert_eq!(lifecycle_session_ids, vec![crate::wal::SessionId::ZERO]);
    }

    #[tokio::test]
    async fn admitted_plain_daemon_turn_preserves_one_nonzero_wal_session() {
        let (runtime, _provider, _home, writer, writer_join) = test_runtime(true, 0).await;
        let segment_path = runtime.active_segment_path.clone();
        execute_admitted_turn(&runtime, "daemon session attribution")
            .await
            .expect("execute admitted daemon turn");
        runtime.close_and_drain().await;
        drop(runtime);
        drop(writer);
        writer_join
            .await
            .expect("join admitted daemon turn writer")
            .expect("admitted daemon turn writer succeeds");

        let wal = std::fs::read(segment_path).expect("read admitted daemon turn WAL");
        let mut scoped_headers = Vec::new();
        crate::wal::scan::for_each_frame(&wal, |_, frame| {
            if matches!(
                frame.header.event_type,
                crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT
                    | crate::wal::events::EVENT_TYPE_RAW_TEXT
                    | crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST
                    | crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
            ) {
                scoped_headers.push((frame.header.event_type, frame.header.session_id));
            }
            Ok(())
        })
        .expect("scan admitted daemon turn WAL");
        for expected_type in [
            crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT,
            crate::wal::events::EVENT_TYPE_RAW_TEXT,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
        ] {
            assert!(
                scoped_headers
                    .iter()
                    .any(|(event_type, _)| *event_type == expected_type),
                "admitted daemon turn persists its required scoped event {expected_type:#04x}"
            );
        }
        let session_id = scoped_headers
            .first()
            .expect("admitted daemon turn has scoped frames")
            .1;
        assert_ne!(session_id, crate::wal::SessionId::ZERO);
        assert!(
            scoped_headers
                .iter()
                .all(|(_, observed)| *observed == session_id),
            "daemon checkpoint, RAW_TEXT, and provider leaves share one session"
        );
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
