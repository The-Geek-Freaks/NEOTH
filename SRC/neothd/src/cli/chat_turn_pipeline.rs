//! Typed, in-process boundary for one admitted chat turn.
//!
//! This module deliberately has no daemon, IPC, persistence schema, or GUI
//! dependency.  The direct CLI adapter supplies the accepted snapshot, the
//! request-local cancellation gate, and its presentation sink.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::chat::{
    BudgetedProviderRequest, ChatArgs, ContextPreloadNotice, DispatchOutput,
    FramedProviderDispatch, LocalChatCommunicationSubject, PostReplyStreamPlan, PreflightOutcome,
    PromptBuildContext, PromptBuildOptions, PromptBundle, ProviderDispatchResult,
    ProviderRequestBoundary, ReplayTurnContext, TurnRouteResolution, build_prompt_bundle,
    context_preload_session_binding, dispatch_provider, emit_chat_notice, emit_chat_output,
    emit_context_preload_notice, emit_retained_code_map_audits, enforce_preflight,
    extract_attachment_contexts, finalize_provider_request, now_unix,
    opaque_chat_post_mint_failure, preserve_code_map_audit_and_writer_failure,
    resolve_chat_turn_route, routing_safe_effective_cap_at, run_post_reply_pipelines,
    skill_route_frame_line,
};
use crate::config::{FreedomConfig, InstancePaths};
use crate::providers::Request;
use crate::wal::events::{
    EVENT_TYPE_EXTENDED, EVENT_TYPE_INCOGNITO_TURN, EVENT_TYPE_RAW_TEXT, ExtendedSubtype,
};

/// Request-local admission gate. Closing this gate prevents the next effect
/// boundary from starting; it never implies a durable cross-client cancel.
#[derive(Clone)]
pub(crate) struct ChatTurnCancellation {
    closed: Arc<AtomicBool>,
    wake: Arc<tokio::sync::Notify>,
}

impl Default for ChatTurnCancellation {
    fn default() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            wake: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl ChatTurnCancellation {
    pub(crate) fn close(&self) {
        let _ = self.try_close();
        self.wake.notify_waiters();
    }

    /// Atomically claim this turn's one cancellation terminal boundary.
    /// Returns `true` only for the caller that moved the gate from open to
    /// closed. A silence watchdog must use this instead of a load-then-store so
    /// an already-linearized user/shutdown cancellation wins its expiry race.
    pub(crate) fn try_close(&self) -> bool {
        let claimed = self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if claimed {
            self.wake.notify_waiters();
        }
        claimed
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Wakeable local cancellation used by an active provider stream.  The
    /// double check closes the notify-registration race without introducing a
    /// polling task or a detached finalizer.
    pub(crate) async fn cancelled(&self) {
        while !self.is_closed() {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            // Register before the second flag read. `Notify` otherwise has a
            // narrow close-between-check-and-await race that could strand a
            // provider stream with no further incoming item.
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn check_open(&self, boundary: &'static str) -> Result<()> {
        anyhow::ensure!(
            !self.closed.load(Ordering::Acquire),
            "chat turn cancelled before {boundary}"
        );
        Ok(())
    }

    pub(crate) fn pre_tool_use_cancellation(&self) -> crate::hooks::PreToolUseCancellation {
        crate::hooks::PreToolUseCancellation::from_chat_turn(Arc::clone(&self.closed))
    }
}

impl crate::security::mirror_refusal_pipeline::MirrorCancellation for ChatTurnCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_closed()
    }

    fn cancelled(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(ChatTurnCancellation::cancelled(self))
    }
}

/// Sanitized presentation events. Provider bytes reach this boundary only
/// after the existing framing/canary validation in `cli::chat`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ChatTurnEvent {
    /// A presentation record already classified by the turn engine.  It is
    /// deliberately not a raw writer callback: framing and stream sequence
    /// values remain explicit data for the CLI renderer.
    Output(ChatOutput),
    Terminal(ChatTurnTerminal),
}

/// Typed user-visible records produced by the in-process turn path.  The
/// direct CLI adapter is the only implementation which maps these records to
/// stdout/stderr or protocol-v3 RS frames.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ChatOutput {
    HumanStdout {
        text: String,
    },
    HumanStderr {
        text: String,
    },
    Notice {
        stream: bool,
        text: String,
    },
    ProviderDelta {
        sequence: u32,
        text: String,
        stream_control_token: Option<String>,
    },
    /// Exact terminal provider body from the contained workflow-replay path.
    /// Presentation adapters ignore it; only the replay scorer consumes it.
    ReplayCompletedBody {
        text: String,
    },
    ReasoningDelta {
        sequence: u32,
        delta: crate::providers::ReasoningText,
        stream_control_token: Option<String>,
    },
    ReasoningState {
        sequence: u32,
        state: crate::providers::ReasoningTerminalState,
        event_count: u64,
        byte_count: u64,
        stream_control_token: Option<String>,
    },
    StreamDone {
        control_token: Option<String>,
        line: String,
    },
    /// Authenticated or sentinel stream frames constructed by the existing
    /// protocol formatter. Provider text never enters this variant.
    StreamFrames {
        frames: String,
    },
    /// A post-provider accepted body for the private GUI transport, paired
    /// with the existing authenticated CLI frames. The direct CLI renders
    /// only `frames`; its body is deliberately never written a second time.
    DeferredProviderFrames {
        frames: String,
        accepted_body: String,
    },
    StreamFinalizationError {
        control_token: String,
        message: String,
    },
    StreamNotice {
        control_token: String,
        kind: String,
        id: String,
        text: String,
        durable: bool,
    },
    LocalStreamCompletion {
        control_token: Option<String>,
        chunk_count: u32,
    },
    SkillRoute {
        control_token: String,
        report_json: String,
    },
    /// Reduced W163 recall presentation captured from the exact same query.
    /// This private typed value carries no recall text or source identity; the
    /// direct CLI ignores it after also emitting its existing raw control
    /// frame, while the daemon GUI maps it to its sealed stream payload.
    RecallChipBatch {
        batch: crate::memory::recall_presentation::RecallChipBatch,
    },
    /// W162's already-produced live state for the daemon GUI path. The inner
    /// producer sequence is distinct from the outer GUI stream sequence.
    LiveThroughputState {
        throughput_sequence: u64,
        state: crate::daemon::live_throughput::LiveThroughputState,
    },
}

/// The sole presentation route for a typed turn engine. The CLI implementation
/// keeps the existing human and authenticated protocol-v2 renderers outside
/// the engine.
pub(crate) trait ChatTurnEventSink: Send {
    fn emit(&mut self, event: ChatTurnEvent) -> Result<()>;
}

// W41 effect admission is implemented only at concrete provider/MCP start
// points. This pipeline must not recreate a broad route-level gate.

pub(crate) fn emit_output(sink: &mut dyn ChatTurnEventSink, output: ChatOutput) -> Result<()> {
    sink.emit(ChatTurnEvent::Output(output))
        .context("emit typed chat output")
}

/// Content-free terminal state. It intentionally carries no prompt or delta
/// plaintext and does not claim a daemon job or a new durable receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChatTurnTerminal {
    Complete {
        provider: String,
        model: String,
        session_id: Option<String>,
        response_feedback: Option<ResponseFeedbackTarget>,
        response_feedback_unavailable: bool,
    },
}

/// Opaque response-feedback capability issued only at the caller's durable
/// terminal boundary. It contains no prompt, reply, provider, or WAL value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseFeedbackTarget {
    pub(crate) response_id: String,
    pub(crate) session_id: String,
    pub(crate) revision: u64,
}

impl ChatTurnTerminal {
    pub(crate) fn set_response_feedback_target(&mut self, target: ResponseFeedbackTarget) {
        let Self::Complete {
            response_feedback,
            response_feedback_unavailable,
            ..
        } = self;
        *response_feedback = Some(target);
        *response_feedback_unavailable = false;
    }

    pub(crate) fn mark_response_feedback_unavailable(&mut self) {
        let Self::Complete {
            response_feedback_unavailable,
            ..
        } = self;
        *response_feedback_unavailable = true;
    }

    pub(crate) fn response_feedback_target(&self) -> Option<&ResponseFeedbackTarget> {
        let Self::Complete {
            response_feedback, ..
        } = self;
        response_feedback.as_ref()
    }

    pub(crate) fn response_feedback_unavailable(&self) -> bool {
        let Self::Complete {
            response_feedback_unavailable,
            ..
        } = self;
        *response_feedback_unavailable
    }
}

/// Emit the terminal only after the caller's existing persistence boundary has
/// completed. This keeps a sink from observing a successful terminal ahead of
/// its already-established WAL result.
pub(crate) fn emit_terminal(
    sink: &mut dyn ChatTurnEventSink,
    terminal: ChatTurnTerminal,
) -> Result<()> {
    sink.emit(ChatTurnEvent::Terminal(terminal))
        .context("emit typed chat terminal")
}

// W38 Slice 2 — engine stores neutral turn input and owned preparation only.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ChatPreparationOutcome {
    Completed,
    Ready(PreparedChatTurn),
}
pub(crate) struct ChatTurnInput {
    pub(crate) message: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) skill: Option<String>,
    pub(crate) system: Option<String>,
    pub(crate) attach: Vec<PathBuf>,
    pub(crate) repository_root: Option<PathBuf>,
    pub(crate) edit: bool,
    pub(crate) resume_from: Option<String>,
    pub(crate) incognito: bool,
    pub(crate) loop_mode: bool,
    pub(crate) iterations: Option<u32>,
    pub(crate) until: Vec<String>,
    pub(crate) stream: bool,
    pub(crate) temperature: Option<f32>,
    pub(crate) top_p: Option<f32>,
    pub(crate) sampling_seed: Option<u64>,
}
pub(crate) struct ChatTurnPreparation {
    pub(crate) config: FreedomConfig,
    pub(crate) ephemeral_consent: crate::consent::EphemeralConsent,
    pub(crate) stream_control_token: Option<Zeroizing<String>>,
    /// Enables typed W162 transport for the daemon GUI, which deliberately
    /// has no CLI stream-control token.
    pub(crate) typed_gui_controls: bool,
    /// Present only for a contained workflow replay. It cannot be supplied by
    /// regular CLI/daemon callers and keeps provider accounting distinct from
    /// transient conversation state.
    pub(crate) replay_context: Option<ReplayTurnContext>,
    /// Exact selected skill binding from the authority-bound replay prompt snapshot.
    pub(crate) replay_selected_skill: Option<crate::cli::chat::ReplaySelectedSkill>,
    pub(crate) reasoning_display: bool,
    pub(crate) cancellation: ChatTurnCancellation,
    pub(crate) session_canary: std::sync::Arc<crate::security::injection_tracker::CanaryToken>,
    pub(crate) instance_paths: InstancePaths,
    pub(crate) first_tour_home: PathBuf,
    pub(crate) selected_config_path: PathBuf,
    pub(crate) prompt: String,
    pub(crate) current_session_id: String,
    /// Opaque attribution capability minted once at the admitted execution
    /// boundary, after the caller has initialized this home's WAL writer.
    /// It is never reconstructed from provider or RPC data.
    pub(crate) wal_session: Option<crate::wal::WalSessionContext>,
    pub(crate) chat_ts_unix: i64,
    pub(crate) mcp_servers: crate::mcp::McpServers,
    pub(crate) scoped_mcp_servers: Vec<String>,
    pub(crate) tweaks: crate::tweaks::Tweaks,
    pub(crate) profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry,
    pub(crate) slash_skill_name: Option<String>,
    pub(crate) explicit_route_requested: bool,
    /// Canonical normal-chat origin. It is minted only from the configured
    /// Left provider topology, never from CLI/RPC request data.
    pub(crate) normal_chat_role: Option<NormalChatRoleBinding>,
}

#[derive(Clone)]
pub(crate) struct NormalChatRoleBinding {
    pub(crate) provider: crate::config::inference::InferenceProvider,
    pub(crate) fixed_config: Arc<FreedomConfig>,
    /// Present only for daemon turns, whose runtime owns an accepted live
    /// controller. Standalone CLI turns intentionally retain the snapshot.
    pub(crate) role_policy_reload: Option<Arc<crate::config::reload::ReloadController>>,
}
pub(crate) struct PreparedChatTurn {
    pub(crate) input: ChatTurnInput,
    pub(crate) preparation: ChatTurnPreparation,
    #[cfg(test)]
    pub(crate) abliterated_loader:
        Option<std::sync::Arc<dyn crate::security::refusal_abliterated::AbliteratedProviderLoader>>,
    pub(crate) deferred_failure_output: Option<ChatOutput>,
    pub(crate) deferred_terminal: Option<ChatTurnTerminal>,
    /// Private proof of the exact durable agent row selected for a possible
    /// response-feedback capability. It remains adapter-local through writer
    /// drain and is never copied into the terminal DTO.
    pub(crate) feedback_eligible_agent_receipt:
        Option<crate::memory::transcript_store::CommittedAgentTurnReceipt>,
}

const LOCAL_CHAT_WAL_SESSION_DOMAIN: &[u8] = b"neoth/wal-session/local-chat-turn/v1\0";

fn admitted_local_chat_identity(current_session_id: &str) -> Result<Vec<u8>> {
    let session_id = current_session_id.as_bytes();
    anyhow::ensure!(
        !session_id.is_empty(),
        "admitted local chat session identity is empty"
    );
    let total_len = LOCAL_CHAT_WAL_SESSION_DOMAIN
        .len()
        .checked_add(std::mem::size_of::<u64>())
        .and_then(|length| length.checked_add(session_id.len()))
        .context("admitted local chat session identity length overflow")?;
    anyhow::ensure!(
        total_len <= crate::wal::MAX_ADMITTED_IDENTITY_BYTES,
        "admitted local chat session identity exceeds WAL context bound"
    );
    let session_len = u64::try_from(session_id.len())
        .context("admitted local chat session identity length exceeds u64")?;
    let mut identity = Vec::with_capacity(total_len);
    identity.extend_from_slice(LOCAL_CHAT_WAL_SESSION_DOMAIN);
    identity.extend_from_slice(&session_len.to_be_bytes());
    identity.extend_from_slice(session_id);
    Ok(identity)
}

fn wal_session_for_admitted_local_turn(
    home: &Path,
    current_session_id: &str,
    incognito: bool,
) -> Result<Option<crate::wal::WalSessionContext>> {
    if incognito {
        return Ok(None);
    }
    let identity = admitted_local_chat_identity(current_session_id)?;
    crate::wal::WalSessionContext::from_admitted_identity(home, &identity)
        .map(Some)
        .context("mint admitted local chat WAL session context")
}

impl PreparedChatTurn {
    /// Bind the local, already-admitted turn to the home whose writer is
    /// already available at the shared execution entry.  The only input is
    /// preparation state created inside the CLI/daemon adapters; provider and
    /// RPC payload metadata cannot choose this header attribution.
    fn mint_wal_session_after_writer_home_initialization(&mut self) -> Result<()> {
        if self.input.incognito {
            self.preparation.wal_session = None;
            return Ok(());
        }
        if self.preparation.wal_session.is_none() {
            self.preparation.wal_session = wal_session_for_admitted_local_turn(
                &self.preparation.first_tour_home,
                &self.preparation.current_session_id,
                false,
            )?;
        }
        Ok(())
    }

    pub(crate) fn take_feedback_eligible_agent_receipt(
        &mut self,
    ) -> Option<crate::memory::transcript_store::CommittedAgentTurnReceipt> {
        self.feedback_eligible_agent_receipt.take()
    }
}
pub(crate) async fn run_prepared_chat_turn(
    prepared: &mut PreparedChatTurn,
    provider: &dyn crate::providers::Provider,
    writer: &crate::wal::writer::WalWriterHandle,
    segment_path: &Path,
    output: &mut dyn ChatTurnEventSink,
) -> Result<Option<ChatOutput>> {
    run_prepared_chat_turn_with_effect_gate(prepared, provider, writer, segment_path, output, None)
        .await
}

pub(crate) async fn run_prepared_chat_turn_with_effect_gate(
    prepared: &mut PreparedChatTurn,
    provider: &dyn crate::providers::Provider,
    writer: &crate::wal::writer::WalWriterHandle,
    segment_path: &Path,
    output: &mut dyn ChatTurnEventSink,
    turn_effect_gate: Option<std::sync::Arc<dyn crate::providers::ChatTurnEffectGate>>,
) -> Result<Option<ChatOutput>> {
    // Every concrete caller reaches this shared entry only after its local or
    // daemon admission succeeds and its home-scoped writer is initialized.
    // Keep the resulting opaque capability on `prepared` for the full turn,
    // including provider retries, fallbacks, and post-reply work.
    prepared
        .mint_wal_session_after_writer_home_initialization()
        .context("bind admitted chat turn to initialized WAL home")?;
    let PreparedChatTurn {
        input,
        preparation:
            ChatTurnPreparation {
                config,
                ephemeral_consent,
                stream_control_token,
                typed_gui_controls,
                replay_context,
                replay_selected_skill: prepared_replay_selected_skill,
                reasoning_display,
                cancellation,
                session_canary,
                instance_paths,
                first_tour_home,
                selected_config_path,
                prompt,
                current_session_id,
                wal_session,
                chat_ts_unix,
                mcp_servers,
                scoped_mcp_servers,
                tweaks,
                profile_extensions,
                slash_skill_name,
                explicit_route_requested,
                normal_chat_role,
            },
        #[cfg(test)]
        abliterated_loader,
        deferred_failure_output,
        deferred_terminal,
        feedback_eligible_agent_receipt: prepared_feedback_eligible_agent_receipt,
    } = prepared;
    let args = ChatArgs {
        message: input.message.clone(),
        workflow: None,
        changing_facts: false,
        model: input.model.clone(),
        skill: input.skill.clone(),
        system: input.system.clone(),
        attach: input.attach.clone(),
        repository_root: input.repository_root.clone(),
        edit: input.edit,
        // This is the caller-admitted selected path, retained for lower
        // compatibility helpers which construct their own reload/action paths.
        config: Some(selected_config_path.clone()),
        wal_segment: None,
        stream: input.stream,
        show_reasoning: *reasoning_display,
        gui_consent_token_stdin: false,
        temperature: input.temperature,
        top_p: input.top_p,
        sampling_seed: input.sampling_seed,
        resume_from: input.resume_from.clone(),
        incognito: input.incognito,
        loop_mode: input.loop_mode,
        iterations: input.iterations,
        until: input.until.clone(),
    };
    let writer = (*writer).clone(); // ── PWF-02: SessionStart MODE_CHECKPOINT (0x9A) ───────────────────────
    // Emit a session-start checkpoint immediately after the WAL writer
    // opens so that `neoth chat --resume-from <hash>` can recover this
    // session's provider / council configuration even if the process
    // crashes before completing a turn. Best-effort: a WAL append failure
    // MUST NOT fail the chat turn.
    //
    // Provider name at this point: the live Provider hasn't been
    // constructed yet (it's passed in via the `provider` argument) but
    // its name() is available from the &dyn Provider reference.
    if !args.incognito {
        use crate::recall::reconstruct::ModeCheckpoint;
        use crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT;
        // GOLD-ADAPT-G-01: three-way label: single > off > enabled.
        let council_mode_str = if config.council.mode.is_single() {
            "single".to_string()
        } else if config.council.disabled.unwrap_or(false) {
            "off".to_string()
        } else {
            "enabled".to_string()
        };
        let mut cp = ModeCheckpoint {
            checkpoint_hash: String::new(),
            session_id: current_session_id.clone(),
            mode: "chat".to_string(),
            provider_target: provider.name().to_string(),
            council_mode: council_mode_str,
            scoped_mcp_servers: scoped_mcp_servers.clone(),
            mcp_scope_recorded: true,
            phase: "chat:session-start".to_string(),
            ts_unix: *chat_ts_unix,
        };
        cp.stamp_hash();
        let payload = serde_json::to_vec(&cp).context("serialize session-start checkpoint")?;
        let hdr = crate::wal::make_header_in(EVENT_TYPE_MODE_CHECKPOINT, &payload, *wal_session);
        writer
            .append(hdr, payload)
            .await
            .context("persist session-start checkpoint")?;
        emit_chat_notice(
            output,
            args.stream,
            format_args!("[neoth] checkpoint: {}", cp.checkpoint_hash),
        )
        .context("write session checkpoint notice")?;
    }

    // Attachment decoding may download a local model and audio/video may enter
    // STT. Start it only after the turn WAL exists so every side effect uses the
    // same durable writer as the eventual provider request. Extraction failures
    // drain the writer before returning.
    let attachment_contexts = match extract_attachment_contexts(
        &args.attach,
        config,
        first_tour_home,
        writer.clone(),
        *wal_session,
    )
    .await
    {
        Ok(contexts) => contexts,
        Err(error) => {
            drop(writer);
            return Err(error);
        }
    };

    // G-03 self-correction signal. Record behavioral evidence only after every
    // requested attachment passed admission and extraction. A rejected turn
    // must not mutate the learned operator profile. The audit stores only a
    // prompt hash (no message-content leak); sustained correction pressure is
    // consumed by the profile-adapt cron.
    if !args.incognito {
        let _ = crate::feedback::record_operator_correction(first_tour_home, prompt).await;
    }

    // ── RAW_TEXT (the actual prompt, for recall) ──────────────────────────
    // Stored before dispatch so `neoth recall "..."` can find what the
    // operator typed.  PROVIDER_REQUEST WAL frame follows later, after the
    // full 6-tier dispatch-model resolution in run_chat_with (post
    // enforce_preflight).  WAL is mode-0600 / DACL-restricted, so raw
    // prompts at rest match the existing trust boundary.
    // ODY-09: incognito turns skip RAW_TEXT entirely — no prompt content in WAL.
    // An INCOGNITO_TURN (0xF7) audit anchor is written instead.
    let mut operator_transcript_persisted = false;
    let raw_event_id = if args.incognito {
        // ODY-09: no prompt stored; raw_event_id=0 signals "no anchor" to the
        // profile-learning pipeline (extract_window gates on valid non-zero ids).
        // This is deliberately metadata-only.  Never add prompt, reply,
        // session, profile, or provider-body fields to the privacy anchor.
        let payload = serde_json::to_vec(&serde_json::json!({
            "ts_unix": now_unix(),
            "incognito": true,
        }))
        .context("serialize incognito audit anchor")?;
        let hdr = crate::wal::make_header(EVENT_TYPE_INCOGNITO_TURN, &payload);
        writer
            .append(hdr, payload)
            .await
            .context("persist incognito audit anchor")?;
        0i64
    } else if let Some(retention) = config.memory.transcript_mining_retention {
        let subject = LocalChatCommunicationSubject::mint();
        let persisted = crate::memory::transcript_mining_runtime::persist_local_operator_turn(
            &subject,
            first_tour_home,
            &writer,
            retention,
            current_session_id,
            *wal_session,
            prompt,
            *chat_ts_unix,
        )
        .await;
        match persisted {
            Ok(event_id) => {
                operator_transcript_persisted = true;
                event_id
            }
            Err(error) => {
                drop(writer);
                return Err(error.context("persist opted-in operator transcript provenance"));
            }
        }
    } else {
        let raw_header =
            crate::wal::make_header_in(EVENT_TYPE_RAW_TEXT, prompt.as_bytes(), *wal_session);
        // Capture the event_id before the header moves into `append` — the
        // post-reply profile-learning pipeline (B-Konsens 2026-05-17 below)
        // uses this as the trigger anchor for `extract_window`.
        let raw_event_id = raw_header.event_id.0 as i64;
        let raw_session_id = raw_header.session_id;
        let origin_payload =
            crate::memory::counterparty_consent::serialize_local_origin_receipt(&raw_header)
                .context("serialize local RAW_TEXT origin receipt")?;
        writer
            .append(raw_header, prompt.as_bytes().to_vec())
            .await
            .context("write RAW_TEXT WAL frame")?;
        let origin_header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &origin_payload)
            .event_subtype(ExtendedSubtype::RawTextOrigin as u8)
            .session(raw_session_id)
            .build();
        if let Err(error) = writer.append(origin_header, origin_payload).await {
            // The raw frame is durable but deliberately remains unknown when
            // this independent metadata receipt cannot be appended.
            tracing::warn!(error = %error, raw_event_id, "W208 RAW_TEXT origin receipt append failed; raw remains unknown");
        }
        raw_event_id
    };

    // ── P-08 briefing-gate marker (Workstream C, Session 22) ──────────────
    // Update the operator-activity timestamp so the cron task's
    // `should_emit_for_briefing` check sees a fresh "operator engaged"
    // signal without re-scanning the WAL. Best-effort: a permission
    // failure on the marker file MUST NOT fail the chat — recording is
    // an audit signal, not a chat-correctness invariant.
    if !args.incognito
        && let Err(error) =
            crate::profile::briefing_gate::record_last_active(first_tour_home, now_unix() as i64)
    {
        tracing::warn!(error = %error, "operator activity marker was not persisted");
    }

    // ── GOLD-WIRE-02: conversational-recall short-circuit ─────────────────
    // "Weißt du noch als wir über X geredet haben?" / "do you remember when
    // we talked about X?" is answered straight from the local idx_episode
    // store WITHOUT an LLM call — so NO PROVIDER_REQUEST / PROVIDER_RESPONSE
    // frame is written for this turn. The RAW_TEXT frame above still records
    // the question so it stays recallable later. The helper is best-effort on
    // the DB (a recall miss yields a localized "nothing found" reply, never
    // an error), and returns `None` for any non-recall prompt — which falls
    // through to the normal provider path below unchanged.
    // GR-039: gated on `memory.recall_shortcut` (default true) so operators
    // can route recall-looking prompts to the provider like any other turn.
    if !args.incognito
        && !*explicit_route_requested
        && attachment_contexts.is_none()
        && config.memory.recall_shortcut
        && let Some(reply) = crate::cli::recall::answer_conversational_recall(
            prompt,
            &first_tour_home.join("views.db"),
        )
        .await
    {
        emit_chat_output(output, ChatOutput::HumanStdout { text: reply })?;
        // Local recall has no provider/post-reply pipeline, but stream consumers
        // still need the same authenticated provider_done -> done terminal
        // lifecycle as every other successful GUI turn.
        // The terminal pair is emitted only after the local turn's WAL writer
        // has drained successfully. A failed writer task leaves stream
        // consumers without a false `done` proof.
        return Ok(args.stream.then(|| ChatOutput::LocalStreamCompletion {
            control_token: stream_control_token.as_ref().map(|token| token.to_string()),
            chunk_count: 1,
        }));
    }

    // ── Early intent hash for pre-assembly skill audit ────────────────────
    //
    // Skill-suppression events can fire while the full bundle is still being
    // assembled, so they receive this A+E intent hash.  The provider request
    // and BUDGET_EXCEEDED event use a second hash computed from the complete,
    // final typed bundle at the budget boundary below.
    let mut bundle_entries: Vec<crate::skills::versioning::BundleBlockEntry<'_>> = Vec::new();
    if let Some(sys) = args.system.as_deref().filter(|s| !s.is_empty()) {
        bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
            block: crate::skills::versioning::BundleBlock::A,
            content: sys,
        });
    }
    bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
        block: crate::skills::versioning::BundleBlock::E,
        content: prompt,
    });
    let intent_bundle_hash = crate::skills::versioning::prompt_bundle_hash_hex(&bundle_entries);

    // Start after this turn's authenticated transcript delivery has committed,
    // so that delivery cannot invalidate our own SQLite snapshot. Incognito
    // never constructs a preloader or reads the existing recall store.
    let recall_binding =
        context_preload_session_binding(config.operator_id.as_deref(), current_session_id);
    let session_recall = if args.incognito {
        None
    } else {
        emit_context_preload_notice(
            output,
            args.stream,
            stream_control_token.as_ref().map(|token| token.as_str()),
            &recall_binding,
            ContextPreloadNotice::Loading,
        )?;
        Some((
            crate::memory::session_start_recall::start_session_recall_preload(
                &LocalChatCommunicationSubject::mint(),
                first_tour_home.clone(),
                &recall_binding,
                prompt,
            ),
            recall_binding.as_str(),
        ))
    };

    // ── Operator context + skills load — K-Perf-4 parallel resource load ──
    // Both reads hit the filesystem and are mutually independent: operator_md
    // assembles ~/.neoth/NEOTH.md + project + rules + memory, skills walks
    // `<home>/skills/`. Running them sequentially was ~2× the wall time on
    // cold caches (each ~5-20ms). tokio::join! drives them concurrently
    // through the same runtime worker — the FS reads pipeline OS-side
    // without extra threads. Per Performance agent's K-Perf-4 pick.
    //
    // The skill router (line below) consumes installed_skills, so loading
    // it BEFORE the system-prompt assembly is mandatory — the parallel
    // load just shaves the serial cost off the front edge.
    let home = first_tour_home.clone();
    let prompt_current_path = std::env::current_dir()
        .context("resolve current working directory for repository-aware prompt assembly")?;
    // GOLD-CCPARITY-SKILLVIS-01 — determine slash-invocation BEFORE calling
    // build_prompt_bundle so the visibility pre-filter can gate NameOnly /
    // UserInvocableOnly skills. We parse the invocation here (before the slash
    // command dispatch in enforce_preflight) and check whether the name matches
    // a skill id. The full slash-command dispatch still runs in enforce_preflight
    // as before — this is a read-only pre-check for the visibility gate only.
    let (
        PromptBundle {
            combined_system,
            context_preload_notice,
            skill_route_guard: _skill_route_guard,
            skill_invocation_policy,
            skill_route_report,
            budget_items,
            mcp_catalogue_slot,
            skill_tool_allowlist,
            plan_attest_hash,
            agent_raw_layers,
            resolved_model: skill_model,
            // GOLD-CCPARITY-EFFORT-03: per-skill effort resolved in build_prompt_bundle.
            resolved_effort: skill_effort,
            skill_loop_trigger,
            repo_recall_audit,
            architecture_recall_audit,
        },
        config,
        prompt,
        home,
    ) = build_prompt_bundle(
        config.clone(),
        prompt.clone(),
        home,
        PromptBuildContext {
            args: &args,
            prompt_bundle_hash: &intent_bundle_hash,
            writer: &writer,
            current_path: &prompt_current_path,
            attachment_contexts: attachment_contexts.as_ref(),
            output,
            stream_control_token: stream_control_token.as_ref().map(|token| token.as_str()),
            session_recall,
        },
        PromptBuildOptions {
            slash_skill_name: slash_skill_name.clone(),
            // B22-TWEAKS-MODEL-01 — pre-loaded fail-loud at the chat boundary.
            persona_override_from_tweaks: tweaks.persona_override.clone(),
            replay_skill_registry: replay_context.as_ref().map(|context| {
                (
                    context.installed_skill_home.clone(),
                    context.installed_skill_config.clone(),
                )
            }),
        },
    )
    .await?;

    let replay_selected_skill = replay_context.as_ref().and_then(|_| {
        (skill_route_report.outcome == crate::skills::resolver::SkillRouteOutcome::Match)
            .then(|| skill_route_report.candidates.first())
            .flatten()
            .map(|candidate| crate::cli::chat::ReplaySelectedSkill {
                id: candidate.skill_id.clone(),
                content_sha256: candidate.execution.content_hash.clone(),
            })
    });
    *prepared_replay_selected_skill = replay_selected_skill;

    if let Some(state) = context_preload_notice {
        emit_context_preload_notice(
            output,
            args.stream,
            stream_control_token.as_ref().map(|token| token.as_str()),
            &recall_binding,
            state,
        )?;
    }

    // Authenticated GUI/Buddy consumers receive the exact shared typed route
    // report once, before any local action or provider delta. Terminal streams
    // stay raw text and therefore never receive this JSON control frame.
    if let Some(control_token) = stream_control_token.as_ref().map(|token| token.as_str()) {
        let frame = skill_route_frame_line(control_token, &skill_route_report)
            .context("build authenticated Skill route frame")?;
        if let Err(error) = emit_chat_output(
            output,
            ChatOutput::SkillRoute {
                control_token: control_token.to_owned(),
                report_json: frame,
            },
        ) {
            drop(writer);
            return Err(error).context("write authenticated Skill route frame");
        }
    }

    let route_failure = match skill_route_report.outcome {
        crate::skills::resolver::SkillRouteOutcome::Conflict => {
            let candidates = skill_route_report
                .candidates
                .iter()
                .map(|candidate| match &candidate.mode_id {
                    Some(mode) => format!("{}/{}", candidate.skill_id, mode),
                    None => candidate.skill_id.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            Some(anyhow::anyhow!(
                "Skill routing conflict at {:?}: {candidates}. Select one explicitly with --skill <id> or /skill-id.",
                skill_route_report.stage
            ))
        }
        crate::skills::resolver::SkillRouteOutcome::Rejected => Some(anyhow::anyhow!(
            "Explicit Skill selection rejected: {:?}",
            skill_route_report.rejection
        )),
        crate::skills::resolver::SkillRouteOutcome::Match
        | crate::skills::resolver::SkillRouteOutcome::NoMatch => None,
    };
    if let Some(error) = route_failure {
        drop(writer);
        return Err(error);
    }

    // GOLD-CCPARITY-ONCE: session-scoped once-guard. One run_chat_with call =
    // one CLI session. Created here before enforce_preflight so the same guard
    // is shared across PrePipeline, PreProviderCall, and PostProviderCall
    // within the single turn (and the same guard is reused across multi-turn
    // batch sessions if run_chat_with is called in a loop). For the CLI path
    // this function is called once per invocation, so the guard lives exactly
    // as long as the session.
    let once_guard = crate::hooks::SessionOnceGuard::new();

    let preflight_outcome = enforce_preflight(
        combined_system,
        budget_items,
        mcp_catalogue_slot,
        prompt,
        provider,
        &args,
        replay_context.is_some(),
        &config,
        writer,
        *wal_session,
        &home,
        plan_attest_hash,
        agent_raw_layers,
        skill_model,
        skill_effort,
        tweaks.model_default.clone(),
        &once_guard,
        ephemeral_consent,
        session_canary,
        output,
    )
    .await;

    let (
        writer,
        review_context,
        final_prompt,
        final_system,
        route_system,
        prompt,
        quota_path,
        quota_tracker,
        hooks,
        effective_model,
        model_source,
        agent_tool_policy,
        pending_block_restorations,
        budget_items,
        mcp_catalogue_slot,
        canary_token,
    ) = match preflight_outcome {
        Err(error) => {
            return Err(error);
        }
        Ok(PreflightOutcome::Done) => {
            return Ok(args.stream.then(|| ChatOutput::LocalStreamCompletion {
                control_token: stream_control_token.as_ref().map(|token| token.to_string()),
                chunk_count: 1,
            }));
        }
        Ok(PreflightOutcome::Continue {
            writer,
            review_context,
            final_prompt,
            final_system,
            route_system,
            prompt,
            quota_path,
            quota_tracker,
            hooks,
            effective_model,
            model_source,
            agent_tool_policy,
            pending_block_restorations,
            budget_items,
            mcp_catalogue_slot,
            canary_token,
        }) => (
            writer,
            review_context,
            final_prompt,
            final_system,
            route_system,
            prompt,
            quota_path,
            quota_tracker,
            hooks,
            effective_model,
            model_source,
            agent_tool_policy,
            pending_block_restorations,
            budget_items,
            mcp_catalogue_slot,
            canary_token,
        ),
    };

    let mut mcp_tool_scope = crate::mcp::McpToolScope::from_skill_allowlist(skill_tool_allowlist);
    if replay_context.is_some() {
        // An active agent scope with an empty allowlist rejects every tool
        // before server lookup, SmartApprove, lease, or transport setup.
        mcp_tool_scope = crate::mcp::McpToolScope::default().with_agent(vec![], vec![]);
    } else if let Some((allowed, disallowed)) = agent_tool_policy {
        mcp_tool_scope = mcp_tool_scope.with_agent(allowed, disallowed);
    }
    // Every complete-body post-provider mutator owns the same user-output
    // boundary. Hooks may Block/Replace; block restoration and refusal
    // recovery may replace bytes. Keep the stream internal until all enabled
    // mutators settle, otherwise visible output and the durable body diverge.
    let defer_provider_output = if replay_context.is_some() {
        // A contained replay accepts only its initial provider completion.
        // Hooks and every post-reply recovery/fallback path are excluded.
        false
    } else {
        hooks.iter().any(|hook| {
            hook.stage == crate::hooks::HookStage::PostProviderCall && hook.enabled.unwrap_or(true)
        }) || !pending_block_restorations.is_empty()
            || (!args.incognito
                && (config.refusal_recovery.enabled
                    || config.refusal_recovery.abliterated_fallback_enabled
                    || (config.refusal_recovery.teacher_escalation_enabled
                        && crate::providers::is_local_provider(provider.name()))))
    };

    let route_thinking_budget = skill_effort
        .filter(|_| provider.request_controls().supports_thinking_budget())
        .map(crate::providers::effort_override::effort_to_tokens);
    let base_route_request = Request {
        prompt: final_prompt.clone(),
        system: route_system,
        model: effective_model.clone(),
        temperature: args.temperature,
        top_p: args.top_p,
        sampling_seed: args.sampling_seed,
        stop_sequences: Vec::new(),
        thinking_budget: route_thinking_budget,
        max_output_tokens: None,
    };
    let TurnRouteResolution {
        route: resolved_chat_route,
        council_skip,
    } = resolve_chat_turn_route(
        &args,
        &config,
        &base_route_request,
        &prompt,
        &home,
        mcp_servers,
        skill_loop_trigger,
        mcp_catalogue_slot.is_some(),
    )
    .await;
    // Replay is one provider turn, never a council, MCP, or refinement route.
    // The empty MCP scope below remains a second, earlier authorization guard.
    let chat_route = if replay_context.is_some() {
        crate::cli::chat::TurnDispatchRoute::Direct
    } else {
        resolved_chat_route
    };
    let recovery_route_eligible = chat_route.supports_single_leaf_recovery();

    let mut budget_items = budget_items;
    let mut final_system = final_system;
    // ── Route-bound MCP catalogue (CLI path) ──────────────────────────────
    // Exact route is fixed above. No Council/MIF/stream/direct turn reaches
    // this await, and dispatch_provider consumes the same route value below.
    let mcp_catalogue: Option<crate::mcp::catalogue::McpPromptCatalogue> =
        if chat_route.uses_mcp_catalogue() && mcp_catalogue_slot.is_some() {
            crate::mcp::catalogue::assemble_catalogue_for_prompt(mcp_servers, &final_prompt).await
        } else {
            None
        };
    if let (Some(slot), Some(catalogue)) = (mcp_catalogue_slot, mcp_catalogue.as_ref()) {
        tracing::info!(
            data_bytes = catalogue.data().as_str().len(),
            source_id = catalogue.source_id().as_str(),
            "MCP tool catalogue injected into system prompt"
        );
        slot.insert(&mut budget_items, catalogue)?;
        let (typed_prompt, typed_system) =
            crate::tokens::budget::render_request(&budget_items).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            typed_prompt == final_prompt,
            "route-bound MCP injection changed the user message"
        );
        final_system = typed_system;
    }

    let route_cap =
        routing_safe_effective_cap_at(&config, provider.name(), effective_model.as_deref(), &home);
    let budgeted = match finalize_provider_request(
        budget_items,
        &final_prompt,
        final_system.as_deref(),
        ProviderRequestBoundary {
            config: &config,
            home: &home,
            provider_name: provider.name(),
            effective_model: effective_model.as_deref(),
            route_cap: Some(route_cap),
            writer: &writer,
        },
    )
    .await
    {
        Ok(request) => request,
        Err(error) => {
            drop(writer);
            return Err(error);
        }
    };
    let BudgetedProviderRequest {
        prompt: final_prompt,
        system: final_system,
        prompt_bundle_hash,
        prompt_token_estimate,
        prompt_tax,
        effective_cap: request_token_cap,
    } = budgeted;
    let retained_code_map_binding = match emit_retained_code_map_audits(
        &writer,
        repo_recall_audit.as_ref(),
        architecture_recall_audit.as_ref(),
        &prompt,
        final_system.as_deref(),
        "cli",
        *wal_session,
    )
    .await
    {
        Ok(binding) => binding,
        Err(error) => {
            drop(writer);
            let audit_error = error
                .context("code-map context audit failed; provider dispatch refused before egress");
            return Err(preserve_code_map_audit_and_writer_failure(audit_error).await);
        }
    };
    // The actual 0x20 intent is emitted centrally for every concrete leaf,
    // after cost/permission approval and immediately before transport dispatch.
    // Carry the old turn-level business fields into those request-bound frames.
    let turn_id = format!("{raw_event_id:016x}");
    let provider_audit_context = crate::providers::cost_authorization::ProviderCallAuditContext {
        source: Some(if replay_context.is_some() {
            "workflow_replay"
        } else {
            "chat"
        }),
        call_type: Some(if replay_context.is_some() {
            "workflow_replay_turn"
        } else {
            "chat_provider_round"
        }),
        request_id: Some(turn_id.clone()),
        operator_id: config.operator_id.clone(),
        session_id: Some(current_session_id.clone()),
        target: Some(crate::profile::runner::extract_target_label(provider.name()).to_owned()),
        model_source: Some(model_source),
        cost_estimate_model: Some(
            effective_model
                .clone()
                .unwrap_or_else(|| "provider_default".to_owned()),
        ),
        prompt_bundle_hash: Some(prompt_bundle_hash.clone()),
        prompt_token_estimate: Some(prompt_token_estimate),
        incognito: args.incognito,
        ..Default::default()
    }
    .with_wal_session(*wal_session)
    .with_prompt_tax(prompt_tax, &final_prompt, final_system.as_deref());

    cancellation.check_open("provider dispatch")?;
    // One shared budget begins at prepared-turn admission and follows any
    // council-shaped post-reply work. Do not mint a fresh cap in a fallback.
    let council_budget = crate::council::BudgetToken::from_council(&config.council);
    let mut silence_watchdog =
        crate::cli::chat_turn_watchdog::TurnSilenceWatchdog::new(cancellation.clone());
    let provider_progress = silence_watchdog.progress_handle();
    // `dispatch_provider` is a very large async state machine. Keep it behind
    // one heap allocation before the watchdog's select state stores it, so the
    // request-local timer does not duplicate that state on narrow test stacks.
    let dispatch = Box::pin(dispatch_provider(
        final_prompt,
        final_system,
        &args,
        provider,
        &config,
        &home,
        writer,
        quota_path,
        quota_tracker,
        request_token_cap,
        mcp_servers,
        mcp_tool_scope,
        // F4/D21 — turn id = the WAL event id, hex; filesystem-safe + unique/turn.
        &turn_id,
        effective_model,
        // GOLD-CCPARITY-EFFORT-03: per-skill reasoning-budget (None = provider default).
        skill_effort,
        model_source,
        provider_audit_context,
        ephemeral_consent,
        chat_route,
        council_skip,
        stream_control_token.as_ref().map(|token| token.as_str()),
        *typed_gui_controls,
        *reasoning_display,
        defer_provider_output,
        &canary_token,
        cancellation,
        &hooks,
        &once_guard,
        turn_effect_gate.clone(),
        skill_invocation_policy,
        normal_chat_role.as_ref(),
        Some(&provider_progress),
        replay_context
            .as_ref()
            .map(|context| context.actual_usage_home.as_path()),
        output,
    ));
    let dispatch_output = match silence_watchdog.race_nonterminal(dispatch).await {
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::Completed(Ok(output)) => {
            // A complete non-streaming provider response is also meaningful
            // progress before the same turn enters post-reply work.
            provider_progress.meaningful_signal();
            output
        }
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::Completed(Err(error)) => {
            // The adapter returned after a transport attempt. Its exact commit
            // cannot be disproven here, so recovery classifies it indeterminate
            // and blocks every fallback/new external leaf for this turn.
            return Err(error);
        }
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::Cancelled => {
            return Err(anyhow::anyhow!(
                "chat turn cancelled during provider dispatch"
            ));
        }
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::SilenceExpired => {
            emit_chat_notice(
                output,
                args.stream,
                "[neoth] provider made no meaningful progress for 120 seconds; retry the turn",
            )
            .context("emit provider silence timeout diagnostic")?;
            return Err(anyhow::Error::new(
                crate::cli::chat_turn_watchdog::TurnSilenceTimeout,
            ));
        }
    };
    let DispatchOutput {
        framed:
            FramedProviderDispatch {
                dispatch:
                    ProviderDispatchResult {
                        completion,
                        stream_chunk_count,
                        ..
                    },
                stream_done_line,
                stream_output_deferred,
                stream_limit_tokens,
            },
        writer,
        recovery_request,
        turn_journal,
        mcp_tool_calls,
        mcp_tool_records,
    } = dispatch_output;

    if replay_context.is_some() {
        anyhow::ensure!(
            mcp_tool_calls == 0 && mcp_tool_records.is_empty(),
            "workflow replay rejected a tool-dispatch result"
        );
        cancellation.check_open("workflow replay terminal")?;
        emit_chat_output(
            output,
            ChatOutput::ReplayCompletedBody {
                text: completion.text.clone(),
            },
        )
        .context("emit contained workflow replay completion body")?;
        *prepared_feedback_eligible_agent_receipt = None;
        *deferred_terminal = Some(ChatTurnTerminal::Complete {
            provider: completion.identity.provider,
            model: completion.identity.wire_model,
            session_id: Some(current_session_id.clone()),
            response_feedback: None,
            response_feedback_unavailable: true,
        });
        return Ok(stream_done_line.map(|line| ChatOutput::StreamDone {
            control_token: stream_control_token.as_ref().map(|token| token.to_string()),
            line,
        }));
    }

    // This is the concrete dispatched completion identity, not a selected
    // config default. Hold it as data until durable post-reply work and the
    // adapter-owned writer drain both succeed.
    let terminal_provider = completion.identity.provider.clone();
    let terminal_model = completion.identity.wire_model.clone();
    let terminal_session_id = current_session_id.clone();
    let stream_control_token_ref = stream_control_token.as_ref().map(|token| token.as_str());
    let is_stream = args.stream;
    cancellation.check_open("post-provider external starts")?;
    let mut feedback_eligible_agent_receipt = None;
    // Post-reply recovery/binding is likewise a large response-producing
    // future. Pin its state on the heap at the watchdog boundary instead of
    // nesting it in the select future's stack frame.
    let post_reply = Box::pin(run_post_reply_pipelines(
        completion,
        writer,
        config,
        council_budget,
        provider,
        args,
        prompt,
        recovery_request,
        recovery_route_eligible,
        review_context,
        hooks,
        segment_path.to_path_buf(),
        raw_event_id,
        instance_paths.clone(),
        profile_extensions.clone(),
        *chat_ts_unix,
        current_session_id.clone(),
        *wal_session,
        operator_transcript_persisted,
        prompt_token_estimate,
        turn_journal,
        &once_guard,
        // GOLD-ADAPT-ODY-20 — thread through for auto-skill extraction gate.
        mcp_tool_calls,
        // REVFIX-EXCERPTS-01 — structured call records for digest-based extraction.
        mcp_tool_records,
        // B22-TWEAKS-MODEL-01 — thread tweaks model for ODY-16 token cap inside pipelines.
        tweaks.model_default.clone(),
        // THEME-TWEAKS-GOLD — render from the same once-loaded snapshot.
        tweaks,
        // GOLD-ADAPT-SKILL-09 — blocks redacted at PreProviderCall by BlockFilter
        // hooks; restored inside run_post_reply_pipelines after PostProviderCall
        // hook stage so WAL/recall never see placeholders.
        pending_block_restorations,
        ephemeral_consent,
        canary_token,
        cancellation,
        turn_effect_gate.clone(),
        normal_chat_role.as_ref(),
        #[cfg(test)]
        abliterated_loader.as_deref(),
        PostReplyStreamPlan {
            control_token: stream_control_token_ref,
            typed_gui_controls: *typed_gui_controls,
            done_line: stream_done_line,
            output_deferred: stream_output_deferred,
            provider_chunk_count: stream_chunk_count,
            limit_tokens: stream_limit_tokens,
        },
        retained_code_map_binding.as_ref(),
        Some(turn_id.as_str()),
        &mut feedback_eligible_agent_receipt,
        output,
    ));
    let post_reply_result = match silence_watchdog.race(post_reply).await {
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::Completed(result) => result,
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::Cancelled => {
            return Err(anyhow::anyhow!(
                "chat turn cancelled during post-provider processing"
            ));
        }
        crate::cli::chat_turn_watchdog::TurnWatchdogPoll::SilenceExpired => {
            emit_chat_notice(
                output,
                is_stream,
                "[neoth] response processing made no meaningful progress for 120 seconds; retry the turn",
            )
            .context("emit post-provider silence timeout diagnostic")?;
            return Err(anyhow::Error::new(
                crate::cli::chat_turn_watchdog::TurnSilenceTimeout,
            ));
        }
    };
    let stream_done_line = match post_reply_result {
        Ok(done_line) => done_line,
        Err(error) => {
            let error = opaque_chat_post_mint_failure("post_reply_pipeline", &error);
            *deferred_failure_output =
                stream_control_token_ref.map(|control_token| ChatOutput::StreamFinalizationError {
                    control_token: control_token.to_owned(),
                    message: error.to_string(),
                });
            return Err(error);
        }
    };
    *prepared_feedback_eligible_agent_receipt = feedback_eligible_agent_receipt;
    *deferred_terminal = Some(ChatTurnTerminal::Complete {
        provider: terminal_provider,
        model: terminal_model,
        session_id: Some(terminal_session_id),
        response_feedback: None,
        response_feedback_unavailable: false,
    });
    Ok(stream_done_line.map(|line| ChatOutput::StreamDone {
        control_token: stream_control_token_ref.map(str::to_owned),
        line,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::providers::{Completion, CompletionIdentity, Provider, Request};

    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct CollectingSink {
        events: Vec<ChatTurnEvent>,
    }

    impl ChatTurnEventSink for CollectingSink {
        fn emit(&mut self, event: ChatTurnEvent) -> Result<()> {
            self.events.push(event);
            Ok(())
        }
    }

    fn retained_skill_registry_context(system: &str) -> String {
        use crate::pipeline::untrusted_context::{GUARD_CLOSE, GUARD_OPEN};

        let mut cursor = 0;
        let mut registry_contexts = Vec::new();
        while let Some(relative_open) = system[cursor..].find(GUARD_OPEN) {
            let start = cursor + relative_open;
            let after_open = start + GUARD_OPEN.len();
            let relative_close = system[after_open..]
                .find(GUARD_CLOSE)
                .expect("every rendered untrusted context must have its canonical closing guard");
            let end = after_open + relative_close + GUARD_CLOSE.len();
            let rendered = &system[start..end];
            if rendered.contains("\"source_id\":\"skills:registry:") {
                assert!(
                    crate::pipeline::untrusted_context::parse_rendered_untrusted(rendered)
                        .is_some(),
                    "Skill registry context must be one complete canonical rendered envelope"
                );
                registry_contexts.push(rendered.to_owned());
            }
            cursor = end;
        }
        assert_eq!(
            registry_contexts.len(),
            1,
            "a request must contain exactly one complete canonical Skill registry context"
        );
        registry_contexts
            .pop()
            .expect("one retained Skill registry context")
    }

    fn refusal_mirror_receipts(bytes: &[u8]) -> Vec<serde_json::Value> {
        let mut receipts = Vec::new();
        crate::wal::scan::for_each_frame(bytes, |_, frame| {
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_REFUSAL_MIRRORED {
                receipts.push(
                    serde_json::from_slice(frame.payload).expect("decode REFUSAL_MIRRORED receipt"),
                );
            }
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8
            {
                let payload: serde_json::Value = serde_json::from_slice(frame.payload)
                    .expect("decode mirror finalization receipt");
                if payload["status"] == "final_reply_prepared" {
                    assert_eq!(
                        receipts.len(),
                        1,
                        "exactly one durable mirror must precede the final reply receipt"
                    );
                }
            }
            Ok(())
        })
        .expect("scan refusal-mirror receipts");
        receipts
    }

    #[derive(Default)]
    struct NeutralEngineProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Provider for NeutralEngineProvider {
        fn name(&self) -> &'static str {
            "neutral-engine-mock"
        }

        fn default_model(&self) -> Option<&str> {
            Some("neutral-engine-model")
        }

        async fn complete(&self, _request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                termination: Default::default(),
                text: "neutral engine completion".to_owned(),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "neutral-engine-model".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "neutral-engine-model".to_owned(),
                latency: Duration::from_millis(1),
                input_tokens: Some(3),
                output_tokens: Some(2),
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    #[derive(Clone)]
    struct W207StreamStep {
        delay: Duration,
        payload: crate::providers::ProviderStreamPayload,
    }

    /// A real event-stream leaf whose admission edge is observable by the
    /// paused-clock turn tests.  The edge is deliberately after all prepared
    /// turn/WAL work: advancing time before it would make a filesystem delay
    /// look like provider silence.
    struct W207DelayedEventProvider {
        steps: Vec<W207StreamStep>,
        stream_calls: AtomicUsize,
        admitted: std::sync::atomic::AtomicBool,
        admitted_notify: std::sync::Arc<tokio::sync::Notify>,
    }

    impl W207DelayedEventProvider {
        fn new(steps: Vec<W207StreamStep>) -> Self {
            Self {
                steps,
                stream_calls: AtomicUsize::new(0),
                admitted: std::sync::atomic::AtomicBool::new(false),
                admitted_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            }
        }

        async fn wait_for_admission(&self) {
            while !self.admitted.load(Ordering::Acquire) {
                let notified = self.admitted_notify.notified();
                tokio::pin!(notified);
                // Register before the second state read, matching the shared
                // cancellation gate's close-between-check-and-await defense.
                notified.as_mut().enable();
                if self.admitted.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        }
    }

    #[async_trait]
    impl Provider for W207DelayedEventProvider {
        fn name(&self) -> &'static str {
            "w207-delayed-event-provider"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w207-delayed-event-model")
        }

        fn streams_on_wire(&self) -> bool {
            true
        }

        async fn complete(&self, _request: Request) -> Result<Completion> {
            anyhow::bail!("W207 fixture must take the real event-stream path")
        }

        async fn stream_events_raw(
            &self,
            _request: Request,
            _permit: &crate::providers::ProviderDispatchPermit,
            _reasoning_display: crate::providers::ReasoningDisplayGrant,
        ) -> Result<crate::providers::ProviderEventStream> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            self.admitted.store(true, Ordering::Release);
            self.admitted_notify.notify_waiters();
            let steps = self.steps.clone();
            let identity = CompletionIdentity {
                provider: self.name().to_owned(),
                wire_model: self.default_model().expect("fixture model").to_owned(),
                dispatch_route: Vec::new(),
            };
            Ok(Box::pin(async_stream::try_stream! {
                for (index, step) in steps.into_iter().enumerate() {
                    tokio::time::sleep(step.delay).await;
                    yield crate::providers::ProviderStreamEvent {
                        identity: identity.clone(),
                        sequence: (index + 1) as u64,
                        payload: step.payload,
                    };
                }
            }))
        }
    }

    fn w207_visible(delta: &str, done: bool) -> crate::providers::ProviderStreamPayload {
        let identity = CompletionIdentity {
            provider: "w207-delayed-event-provider".to_owned(),
            wire_model: "w207-delayed-event-model".to_owned(),
            dispatch_route: Vec::new(),
        };
        let chunk = crate::providers::CompletionChunk {
            delta: delta.to_owned(),
            done,
            identity,
            termination: Default::default(),
            input_tokens: done.then_some(3),
            output_tokens: done.then_some(2),
            cache_creation_tokens: None,
            cache_read_tokens: None,
        };
        if done {
            crate::providers::ProviderStreamPayload::Done { chunk }
        } else {
            crate::providers::ProviderStreamPayload::VisibleText { chunk }
        }
    }

    fn w207_prepared_turn(
        home_path: std::path::PathBuf,
        cancellation: ChatTurnCancellation,
    ) -> PreparedChatTurn {
        let selected_config_path = home_path.join("freedom.yaml");
        let instance_paths = InstancePaths::new(&home_path, &selected_config_path);
        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".to_owned()),
            provider_model: Some("w207-delayed-event-model".to_owned()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        PreparedChatTurn {
            input: ChatTurnInput {
                message: Some("W207 streaming prompt".to_owned()),
                model: Some("w207-delayed-event-model".to_owned()),
                skill: None,
                system: None,
                attach: Vec::new(),
                repository_root: None,
                edit: false,
                resume_from: None,
                incognito: false,
                loop_mode: false,
                iterations: None,
                until: Vec::new(),
                stream: true,
                temperature: None,
                top_p: None,
                sampling_seed: None,
            },
            preparation: ChatTurnPreparation {
                config,
                ephemeral_consent: crate::consent::EphemeralConsent::default(),
                stream_control_token: None,
                typed_gui_controls: false,
                replay_context: None,
                replay_selected_skill: None,
                reasoning_display: false,
                cancellation,
                session_canary: std::sync::Arc::new(
                    crate::security::injection_tracker::CanaryToken::generate()
                        .expect("mint W207 session canary"),
                ),
                instance_paths,
                first_tour_home: home_path,
                selected_config_path,
                prompt: "W207 streaming prompt".to_owned(),
                current_session_id: "w207-streaming-regression".to_owned(),
                wal_session: None,
                chat_ts_unix: 1_725_000_207,
                mcp_servers: crate::mcp::McpServers::default(),
                scoped_mcp_servers: Vec::new(),
                tweaks: crate::tweaks::Tweaks::default(),
                profile_extensions:
                    crate::profile::extension_registry::TypedExtensionRegistry::default(),
                slash_skill_name: None,
                explicit_route_requested: false,
                normal_chat_role: None,
            },
            abliterated_loader: None,
            deferred_failure_output: None,
            deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
        }
    }

    async fn run_w207_stream_turn(
        provider: std::sync::Arc<W207DelayedEventProvider>,
        cancellation: ChatTurnCancellation,
    ) -> (Result<Option<ChatOutput>>, PreparedChatTurn, CollectingSink) {
        let home = tempfile::tempdir().expect("create W207 home");
        let home_path = home.path().to_path_buf();
        let wal_dir = home_path.join("wal");
        std::fs::create_dir_all(&wal_dir).expect("create W207 WAL directory");
        crate::consent::grant(&home_path, ProviderKind::ClaudeCli)
            .expect("grant W207 fixture provider consent");
        let mut prepared = w207_prepared_turn(home_path.clone(), cancellation);
        let segment_path = wal_dir.join("w207-000001.wal");
        let (writer, writer_completion) =
            crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home_path)
                .expect("spawn W207 caller-owned WAL writer");
        let mut sink = CollectingSink::default();
        let result = run_prepared_chat_turn(
            &mut prepared,
            provider.as_ref(),
            &writer,
            &segment_path,
            &mut sink,
        )
        .await;
        drop(writer);
        writer_completion
            .wait()
            .await
            .expect("caller drains W207 WAL before returning its assertion state");
        (result, prepared, sink)
    }

    /// The first call is the real foreground reply. The second is the first
    /// provider call of the two-stage review gate, which only runs after
    /// `dispatch_provider` has returned a completion to post-reply work.
    struct W207PostReplyReviewProvider {
        calls: AtomicUsize,
        review_entered: std::sync::atomic::AtomicBool,
        review_notify: std::sync::Arc<tokio::sync::Notify>,
    }

    impl W207PostReplyReviewProvider {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                review_entered: std::sync::atomic::AtomicBool::new(false),
                review_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            }
        }

        async fn wait_for_review_call(&self) {
            while !self.review_entered.load(Ordering::Acquire) {
                let notified = self.review_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.review_entered.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        }
    }

    #[async_trait]
    impl Provider for W207PostReplyReviewProvider {
        fn name(&self) -> &'static str {
            "w207-post-reply-review-provider"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w207-post-reply-review-model")
        }

        async fn complete(&self, _request: Request) -> Result<Completion> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Ok(Completion {
                    text: "primary W207 reply".to_owned(),
                    identity: CompletionIdentity {
                        provider: self.name().to_owned(),
                        wire_model: self.default_model().expect("fixture model").to_owned(),
                        dispatch_route: Vec::new(),
                    },
                    model: self.default_model().expect("fixture model").to_owned(),
                    ..Default::default()
                });
            }
            assert_eq!(call, 1, "W207 waits at the first post-reply review call");
            self.review_entered.store(true, Ordering::Release);
            self.review_notify.notify_waiters();
            tokio::time::sleep(Duration::from_secs(121)).await;
            anyhow::bail!("W207 review call must be cancelled by the shared turn watchdog")
        }
    }

    async fn run_w207_post_reply_review_turn(
        provider: std::sync::Arc<W207PostReplyReviewProvider>,
        cancellation: ChatTurnCancellation,
    ) -> (Result<Option<ChatOutput>>, PreparedChatTurn, CollectingSink) {
        let home = tempfile::tempdir().expect("create W207 post-reply home");
        let home_path = home.path().to_path_buf();
        let wal_dir = home_path.join("wal");
        let agent_dir = home_path.join("agents");
        std::fs::create_dir_all(&wal_dir).expect("create W207 post-reply WAL directory");
        std::fs::create_dir_all(&agent_dir).expect("create W207 review agent directory");
        std::fs::write(
            agent_dir.join("w207-review.toml"),
            "name = \"w207-review\"\ndescription = \"W207 test reviewer\"\nsystem = \"Review the response.\"\nmodel = \"w207-post-reply-review-model\"\n",
        )
        .expect("write W207 review-agent fixture");
        crate::consent::grant(&home_path, ProviderKind::ClaudeCli)
            .expect("grant W207 post-reply fixture provider consent");
        let mut prepared = w207_prepared_turn(home_path.clone(), cancellation);
        let review_prompt = "/agent w207-review assess the reply".to_owned();
        prepared.input.message = Some(review_prompt.clone());
        prepared.input.model = Some("w207-post-reply-review-model".to_owned());
        prepared.preparation.prompt = review_prompt;
        prepared.preparation.config.provider_model =
            Some("w207-post-reply-review-model".to_owned());
        prepared.preparation.config.review_gate_enabled = true;
        let segment_path = wal_dir.join("w207-post-reply-review-000001.wal");
        let (writer, writer_completion) =
            crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home_path)
                .expect("spawn W207 post-reply caller-owned WAL writer");
        let mut sink = CollectingSink::default();
        let result = run_prepared_chat_turn(
            &mut prepared,
            provider.as_ref(),
            &writer,
            &segment_path,
            &mut sink,
        )
        .await;
        drop(writer);
        writer_completion
            .wait()
            .await
            .expect("caller drains W207 post-reply WAL before asserting");
        (result, prepared, sink)
    }

    /// Records the concrete requests of an initial native refusal plus its
    /// truthful retry.  Keeping this beside the prepared-turn fixture proves
    /// the production adapter, rather than only the metadata helper, carries
    /// the exact retained context through a response replacement.
    #[derive(Default)]
    struct RetainedContextRetryProvider {
        requests: Mutex<Vec<Request>>,
    }

    #[async_trait]
    impl Provider for RetainedContextRetryProvider {
        fn name(&self) -> &'static str {
            "retained-context-retry-mock"
        }

        fn default_model(&self) -> Option<&str> {
            Some("retained-context-retry-model")
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            let mut requests = self.requests.lock().expect("lock captured requests");
            let attempt = requests.len();
            requests.push(request);
            drop(requests);

            if attempt == 0 {
                return Ok(Completion {
                    text: String::new(),
                    termination: crate::providers::ProviderTermination::refused(
                        Some("safety_policy".to_owned()),
                        crate::providers::RefusalOrigin::ProviderMessage,
                        "safety_policy",
                        Some("This request violates safety policy.".to_owned()),
                    ),
                    identity: CompletionIdentity {
                        provider: self.name().to_owned(),
                        wire_model: "retained-context-retry-model".to_owned(),
                        dispatch_route: Vec::new(),
                    },
                    model: "retained-context-retry-model".to_owned(),
                    latency: Duration::from_millis(1),
                    input_tokens: Some(3),
                    output_tokens: Some(0),
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                    usage_measurements: None,
                });
            }

            Ok(Completion {
                termination: Default::default(),
                text: "recovered reply after the truthful retry".to_owned(),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "retained-context-retry-model".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "retained-context-retry-model".to_owned(),
                latency: Duration::from_millis(1),
                input_tokens: Some(3),
                output_tokens: Some(5),
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    #[derive(Default)]
    struct RetainedContextFallbackCloudProvider {
        requests: Mutex<Vec<Request>>,
    }

    #[async_trait]
    impl Provider for RetainedContextFallbackCloudProvider {
        fn name(&self) -> &'static str {
            "retained-context-fallback-cloud"
        }
        fn default_model(&self) -> Option<&str> {
            Some("retained-context-fallback-model")
        }
        async fn complete(&self, request: Request) -> Result<Completion> {
            let mut requests = self.requests.lock().expect("lock fallback cloud requests");
            let attempt = requests.len();
            requests.push(request);
            drop(requests);
            assert!(
                attempt < 2,
                "the fixture requires the shared budget to suppress a third cloud dispatch"
            );
            Ok(Completion {
                text: String::new(),
                termination: crate::providers::ProviderTermination::refused(
                    Some("safety_policy".to_owned()),
                    crate::providers::RefusalOrigin::ProviderMessage,
                    "safety_policy",
                    Some("This request violates safety policy.".to_owned()),
                ),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "retained-context-fallback-model".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "retained-context-fallback-model".to_owned(),
                ..Default::default()
            })
        }
    }

    struct RetainedContextFallbackLocalProvider {
        requests: std::sync::Arc<Mutex<Vec<Request>>>,
    }
    #[async_trait]
    impl Provider for RetainedContextFallbackLocalProvider {
        fn name(&self) -> &'static str {
            "retained-context-fallback-local"
        }
        fn default_model(&self) -> Option<&str> {
            Some("retained-context-fallback-local-model")
        }
        async fn complete(&self, request: Request) -> Result<Completion> {
            self.requests
                .lock()
                .expect("lock fallback local requests")
                .push(request);
            Ok(Completion {
                text: "local shadow draft".to_owned(),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "retained-context-fallback-local-model".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "retained-context-fallback-local-model".to_owned(),
                ..Default::default()
            })
        }
    }

    struct RetainedContextFallbackLoader {
        local_requests: std::sync::Arc<Mutex<Vec<Request>>>,
    }
    #[async_trait]
    impl crate::security::refusal_abliterated::AbliteratedProviderLoader
        for RetainedContextFallbackLoader
    {
        async fn load(&self, model: &str) -> Result<Box<dyn Provider>> {
            assert_eq!(model, "fixture-local-abliterated-model");
            Ok(Box::new(RetainedContextFallbackLocalProvider {
                requests: std::sync::Arc::clone(&self.local_requests),
            }))
        }
    }

    const W137_SELECTED_SKILL_ID: &str = "w137-selected";
    const W137_SELECTED_A_BODY: &str = "W137_SELECTED_A_BODY";
    const W137_SELECTED_B_BODY: &str = "W137_SELECTED_B_BODY";
    const W137_DISABLED_BODY: &str = "W137_DISABLED_APPROVED_CANDIDATE_BODY";
    const W137_REJECTED_BODY: &str = "W137_AUTHORITY_REJECTED_CANDIDATE_BODY";

    fn w137_skill_manifest(description: &str, body: &str, model: &str, effort: &str) -> String {
        format!(
            "id: {W137_SELECTED_SKILL_ID}\n\
             description: {description}\n\
             trigger_keywords: [w137-retained-session]\n\
             system_prompt: {body}\n\
             tool_allowlist: [w137::allowed]\n\
             model: {model}\n\
             effort: {effort}\n"
        )
    }

    fn w137_write_installed_skill(home: &std::path::Path, id: &str, manifest: &str) {
        let skill_dir = home.join("skills").join(id);
        std::fs::create_dir_all(&skill_dir).expect("create W137 installed Skill directory");
        std::fs::write(skill_dir.join("skill.yaml"), manifest)
            .expect("write W137 installed Skill manifest");
    }

    fn w137_record_install_incarnation(home: &std::path::Path, id: &str) {
        let current = crate::skills::installer::inspect_current_install(&home.join("skills"), id)
            .expect("inspect W137 exact installed Skill generation");
        crate::skills::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            crate::skills::installer::SkillMutationOrigin::CliInstall,
        )
        .expect("record W137 authenticated install incarnation");
    }

    fn w137_publish_authority(
        home: &std::path::Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
        state: crate::skills::authority::SkillAuthorityState,
        reason: Option<&str>,
    ) {
        let decision = crate::skills::authority::SkillAuthorityDecision::new(
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
            state,
            reason.map(str::to_owned),
        )
        .expect("construct W137 authority decision");
        crate::skills::authority::publish_installed_authority_decision(home, id, reload, decision)
            .expect("publish W137 authenticated authority decision");
    }

    /// Publishes B only after capturing the first real provider request. The
    /// second cloud request and the local-shadow request therefore exercise
    /// recovery after a durable, newly-authorized registry generation exists.
    struct W137SnapshotPublishingFallbackCloudProvider {
        home: std::path::PathBuf,
        reload: std::sync::Arc<crate::config::reload::ReloadController>,
        requests: Mutex<Vec<Request>>,
        published_b: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Provider for W137SnapshotPublishingFallbackCloudProvider {
        fn name(&self) -> &'static str {
            "w137-snapshot-publishing-cloud"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w137-cloud-default")
        }

        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            crate::providers::ProviderRequestControls::THINKING_BUDGET
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            let attempt = {
                let mut requests = self.requests.lock().expect("lock W137 cloud requests");
                let attempt = requests.len();
                requests.push(request);
                attempt
            };
            assert!(
                attempt < 2,
                "W137 fixture permits one truthful retry before local shadow"
            );

            if attempt == 0 {
                w137_write_installed_skill(
                    &self.home,
                    W137_SELECTED_SKILL_ID,
                    &w137_skill_manifest(
                        "W137 selected B registry description",
                        W137_SELECTED_B_BODY,
                        "w137-b-model",
                        "low",
                    ),
                );
                w137_record_install_incarnation(&self.home, W137_SELECTED_SKILL_ID);
                w137_publish_authority(
                    &self.home,
                    W137_SELECTED_SKILL_ID,
                    self.reload.as_ref(),
                    crate::skills::authority::SkillAuthorityState::Active,
                    None,
                );
                self.published_b.store(true, Ordering::SeqCst);
            }

            Ok(Completion {
                text: String::new(),
                termination: crate::providers::ProviderTermination::refused(
                    Some("safety_policy".to_owned()),
                    crate::providers::RefusalOrigin::ProviderMessage,
                    "safety_policy",
                    Some("This request violates safety policy.".to_owned()),
                ),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "w137-cloud-default".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "w137-cloud-default".to_owned(),
                ..Default::default()
            })
        }
    }

    #[derive(Default)]
    struct W137FreshSessionProvider {
        requests: Mutex<Vec<Request>>,
    }

    #[async_trait]
    impl Provider for W137FreshSessionProvider {
        fn name(&self) -> &'static str {
            "w137-fresh-session-provider"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w137-fresh-default")
        }

        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            crate::providers::ProviderRequestControls::THINKING_BUDGET
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            self.requests
                .lock()
                .expect("lock W137 fresh-session requests")
                .push(request);
            Ok(Completion {
                text: "W137 fresh-session completion".to_owned(),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "w137-fresh-default".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "w137-fresh-default".to_owned(),
                ..Default::default()
            })
        }
    }

    /// Drives the real MCP loop while making the first provider boundary prove
    /// that automatic-context's unavailable receipt is already durable.
    struct ChatConsumerMcpProvider {
        segment_path: std::path::PathBuf,
        requests: std::sync::Mutex<Vec<Request>>,
        first_call_saw_w55_receipt: AtomicBool,
    }

    impl ChatConsumerMcpProvider {
        fn new(segment_path: std::path::PathBuf) -> Self {
            Self {
                segment_path,
                requests: std::sync::Mutex::new(Vec::new()),
                first_call_saw_w55_receipt: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl Provider for ChatConsumerMcpProvider {
        fn name(&self) -> &'static str {
            "chat-consumer-mcp-mock"
        }

        fn default_model(&self) -> Option<&str> {
            Some("chat-consumer-mcp-model")
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            let mut requests = self.requests.lock().expect("lock captured MCP requests");
            let attempt = requests.len();
            requests.push(request);
            drop(requests);

            if attempt == 0 {
                let wal = std::fs::read(&self.segment_path)
                    .expect("the caller-owned WAL is readable before the provider starts");
                self.first_call_saw_w55_receipt.store(
                    wal.windows(b"enabled_context_unavailable".len())
                        .any(|window| window == b"enabled_context_unavailable")
                        && wal
                            .windows(b"\"surface\":\"cli\"".len())
                            .any(|window| window == b"\"surface\":\"cli\"")
                        && wal
                            .windows(b"unmapped_root".len())
                            .any(|window| window == b"unmapped_root"),
                    Ordering::SeqCst,
                );
                return Ok(Completion {
                    termination: Default::default(),
                    text: "```mcp-tool-call\n{\"server\":\"neoth-codegraph\",\"tool\":\"codegraph_recall_v1\",\"arguments\":{\"prompt\":\"leaf_n\",\"limit\":1}}\n```".to_owned(),
                    identity: CompletionIdentity {
                        provider: self.name().to_owned(),
                        wire_model: "chat-consumer-mcp-model".to_owned(),
                        dispatch_route: Vec::new(),
                    },
                    model: "chat-consumer-mcp-model".to_owned(),
                    latency: Duration::from_millis(1),
                    input_tokens: Some(3),
                    output_tokens: Some(1),
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                    usage_measurements: None,
                });
            }

            Ok(Completion {
                termination: Default::default(),
                text: "final chat consumer response".to_owned(),
                identity: CompletionIdentity {
                    provider: self.name().to_owned(),
                    wire_model: "chat-consumer-mcp-model".to_owned(),
                    dispatch_route: Vec::new(),
                },
                model: "chat-consumer-mcp-model".to_owned(),
                latency: Duration::from_millis(1),
                input_tokens: Some(3),
                output_tokens: Some(4),
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    /// The prompt builder intentionally resolves repository context from the
    /// active working directory.  This test-only guard restores process state
    /// after the isolated, seeded repository fixture completes.
    struct PipelineCwdGuard {
        original: std::path::PathBuf,
    }

    impl PipelineCwdGuard {
        fn enter(path: &std::path::Path) -> Self {
            let original = std::env::current_dir().expect("capture test working directory");
            std::env::set_current_dir(path).expect("enter seeded code-map repository");
            Self { original }
        }
    }

    impl Drop for PipelineCwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn seed_pipeline_repo_context(home: &std::path::Path, repo: &std::path::Path) -> InstancePaths {
        let source = repo.join("src/retained_context_marker.rs");
        std::fs::create_dir_all(source.parent().expect("source parent"))
            .expect("create fixture source directory");
        std::fs::write(&source, "pub fn retained_context_marker() {}\n")
            .expect("write indexed marker source");
        let paths = InstancePaths::for_home(home);
        let root = crate::code_map::CanonicalRepoRoot::discover(repo)
            .expect("discover seeded fixture repository");
        crate::code_map::rebuild_snapshot(
            &root,
            &paths.code_map,
            crate::code_map::RebuildOptions::default(),
        )
        .expect("persist seeded code-map snapshot");
        paths
    }

    #[test]
    fn closed_gate_refuses_the_next_effect_boundary() {
        let cancel = ChatTurnCancellation::default();
        cancel.close();
        let error = cancel
            .check_open("provider dispatch")
            .expect_err("closed gate must refuse a provider effect");
        assert!(error.to_string().contains("provider dispatch"));
    }

    #[tokio::test]
    async fn cancellation_wakes_a_pending_stream_wait_without_polling() {
        let cancellation = ChatTurnCancellation::default();
        let pending_wait = cancellation.clone();
        let waiter = tokio::spawn(async move {
            pending_wait.cancelled().await;
        });
        tokio::task::yield_now().await;
        cancellation.close();
        tokio::time::timeout(std::time::Duration::from_millis(100), waiter)
            .await
            .expect("close must wake a stream-select cancellation branch")
            .expect("cancellation waiter must not panic");
    }

    #[tokio::test]
    async fn neutral_engine_runs_a_caller_borrowed_provider_before_caller_drain_and_terminal() {
        let home = tempfile::tempdir().expect("create neutral engine home");
        let home_path = home.path().to_path_buf();
        let selected_config_path = home_path.join("freedom.yaml");
        let instance_paths = InstancePaths::new(&home_path, &selected_config_path);
        let wal_dir = home_path.join("wal");
        std::fs::create_dir_all(&wal_dir).expect("create neutral engine WAL directory");
        crate::consent::grant(&home_path, ProviderKind::ClaudeCli)
            .expect("grant the fixture's accepted provider consent");

        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".to_owned()),
            provider_model: Some("neutral-engine-model".to_owned()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;

        let mut prepared = PreparedChatTurn {
            input: ChatTurnInput {
                message: Some("neutral engine prompt".to_owned()),
                model: Some("neutral-engine-model".to_owned()),
                skill: None,
                system: None,
                attach: Vec::new(),
                repository_root: None,
                edit: false,
                resume_from: None,
                incognito: false,
                loop_mode: false,
                iterations: None,
                until: Vec::new(),
                stream: false,
                temperature: None,
                top_p: None,
                sampling_seed: None,
            },
            preparation: ChatTurnPreparation {
                config,
                ephemeral_consent: crate::consent::EphemeralConsent::default(),
                stream_control_token: None,
                typed_gui_controls: false,
                replay_context: None,
                replay_selected_skill: None,
                reasoning_display: false,
                cancellation: ChatTurnCancellation::default(),
                session_canary: std::sync::Arc::new(
                    crate::security::injection_tracker::CanaryToken::generate()
                        .expect("mint session canary"),
                ),
                instance_paths,
                first_tour_home: home_path.clone(),
                selected_config_path,
                prompt: "neutral engine prompt".to_owned(),
                current_session_id: "neutral-engine-regression".to_owned(),
                wal_session: None,
                chat_ts_unix: 1_725_000_000,
                mcp_servers: crate::mcp::McpServers::default(),
                scoped_mcp_servers: Vec::new(),
                tweaks: crate::tweaks::Tweaks::default(),
                profile_extensions:
                    crate::profile::extension_registry::TypedExtensionRegistry::default(),
                slash_skill_name: None,
                explicit_route_requested: false,
                normal_chat_role: None,
            },
            abliterated_loader: None,
            deferred_failure_output: None,
            deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
        };
        let segment_path = wal_dir.join("neutral-engine-000001.wal");
        let (writer, writer_completion) =
            crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home_path)
                .expect("spawn caller-owned WAL writer");
        let provider = NeutralEngineProvider::default();
        let mut sink = CollectingSink::default();
        assert!(
            prepared.deferred_terminal.is_none(),
            "accepted preparation has no terminal before the engine succeeds"
        );

        let deferred_output = crate::cli::chat_turn_pipeline::run_prepared_chat_turn(
            &mut prepared,
            &provider,
            &writer,
            &segment_path,
            &mut sink,
        )
        .await
        .expect("neutral engine accepts the caller-owned provider and writer");

        prepared.preparation.cancellation.close();
        assert!(
            prepared
                .preparation
                .cancellation
                .check_open("caller completed the turn")
                .is_err(),
            "the caller closes retained cancellation clones after the engine returns"
        );

        assert!(
            deferred_output.is_none(),
            "non-stream turn has no deferred done output"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(sink.events.iter().any(|event| matches!(
            event,
            ChatTurnEvent::Output(ChatOutput::HumanStdout { text })
                if text == "neutral engine completion"
        )));
        assert!(
            !sink
                .events
                .iter()
                .any(|event| matches!(event, ChatTurnEvent::Terminal(_))),
            "the engine must not emit the terminal before its caller drains WAL"
        );
        assert!(matches!(
            prepared.deferred_terminal.as_ref(),
            Some(ChatTurnTerminal::Complete {
                provider,
                model,
                session_id,
                response_feedback: None,
                response_feedback_unavailable: false,
            })
                if provider == "neutral-engine-mock"
                    && model == "neutral-engine-model"
                    && session_id.as_deref() == Some("neutral-engine-regression")
        ));
        let wal_session = prepared
            .preparation
            .wal_session
            .expect("admitted local turn retains its WAL session context");
        assert_ne!(
            wal_session.header_id(),
            crate::wal::SessionId::ZERO,
            "accepted non-incognito turn never retains zero attribution"
        );

        drop(writer);
        writer_completion
            .wait()
            .await
            .expect("caller drains the real WAL writer");
        let wal = std::fs::read(&segment_path).expect("read default-off pipeline WAL");
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
        .expect("scan admitted local turn WAL frames");
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
                "admitted local turn persists its required scoped event {expected_type:#04x}"
            );
        }
        assert!(
            scoped_headers
                .iter()
                .all(|(_, session_id)| *session_id == wal_session.header_id()),
            "checkpoint, RAW_TEXT, and provider leaves preserve one admitted WAL session"
        );
        assert!(
            !wal.windows(b"retained_in_provider_request".len())
                .any(|window| window == b"retained_in_provider_request")
                && !wal
                    .windows(b"final_reply_prepared".len())
                    .any(|window| window == b"final_reply_prepared"),
            "default-off code-map context must not create retained or prepared binding records"
        );
        assert!(
            !sink
                .events
                .iter()
                .any(|event| matches!(event, ChatTurnEvent::Terminal(_))),
            "draining alone cannot publish the deferred terminal"
        );
        emit_terminal(
            &mut sink,
            prepared
                .deferred_terminal
                .take()
                .expect("successful engine leaves its terminal for the caller"),
        )
        .expect("caller publishes terminal only after drain");
        assert!(matches!(
            sink.events.last(),
            Some(ChatTurnEvent::Terminal(ChatTurnTerminal::Complete { provider, model, .. }))
                if provider == "neutral-engine-mock" && model == "neutral-engine-model"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn w207_nonempty_stream_deltas_keep_the_actual_prepared_turn_alive_past_120_seconds() {
        let provider = std::sync::Arc::new(W207DelayedEventProvider::new(vec![
            W207StreamStep {
                delay: Duration::from_secs(119),
                payload: w207_visible("first", false),
            },
            W207StreamStep {
                delay: Duration::from_secs(119),
                payload: w207_visible(" second", false),
            },
            W207StreamStep {
                delay: Duration::from_secs(119),
                payload: crate::providers::ProviderStreamPayload::ReasoningTerminal {
                    state: crate::providers::ReasoningTerminalState::Hidden,
                },
            },
            W207StreamStep {
                delay: Duration::ZERO,
                payload: w207_visible(" done", true),
            },
        ]));
        let cancellation = ChatTurnCancellation::default();
        let turn = tokio::spawn(run_w207_stream_turn(
            std::sync::Arc::clone(&provider),
            cancellation,
        ));
        provider.wait_for_admission().await;

        for signal_index in 0..3 {
            tokio::time::advance(Duration::from_secs(119)).await;
            tokio::task::yield_now().await;
            if signal_index < 2 {
                assert!(
                    !turn.is_finished(),
                    "a meaningful provider delta must rearm the prepared-turn watchdog"
                );
            }
        }
        tokio::task::yield_now().await;
        let (result, prepared, sink) = turn.await.expect("join W207 live stream turn");

        assert!(
            result.is_ok(),
            "timely visible deltas complete the real turn"
        );
        assert_eq!(provider.stream_calls.load(Ordering::SeqCst), 1);
        assert!(prepared.deferred_failure_output.is_none());
        assert!(prepared.deferred_terminal.is_some());
        // Default refusal recovery defers visible stream output until post-reply
        // mutation settles; the canonical accepted body is then one StreamFrames record.
        let visible_output = sink
            .events
            .iter()
            .filter_map(|event| match event {
                ChatTurnEvent::Output(ChatOutput::StreamFrames { frames }) => Some(frames.as_str()),
                _ => None,
            })
            .collect::<String>();
        assert_eq!(visible_output, "first second done");
    }

    #[tokio::test(start_paused = true)]
    async fn w207_silent_or_metadata_only_events_expire_once_without_done_terminal_or_retry() {
        let provider = std::sync::Arc::new(W207DelayedEventProvider::new(vec![
            W207StreamStep {
                delay: Duration::ZERO,
                payload: w207_visible("", false),
            },
            W207StreamStep {
                delay: Duration::ZERO,
                payload: crate::providers::ProviderStreamPayload::ReasoningTerminal {
                    state: crate::providers::ReasoningTerminalState::Hidden,
                },
            },
            W207StreamStep {
                delay: Duration::from_secs(121),
                payload: w207_visible("too late", false),
            },
        ]));
        let turn = tokio::spawn(run_w207_stream_turn(
            std::sync::Arc::clone(&provider),
            ChatTurnCancellation::default(),
        ));
        provider.wait_for_admission().await;
        tokio::task::yield_now().await;
        tokio::time::advance(crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT).await;
        tokio::task::yield_now().await;
        let (result, prepared, sink) = turn.await.expect("join W207 silence turn");

        let error = result.expect_err("metadata-only stream traffic must time out");
        assert!(
            error
                .downcast_ref::<crate::cli::chat_turn_watchdog::TurnSilenceTimeout>()
                .is_some(),
            "the prepared turn returns the typed silence result exactly once"
        );
        assert_eq!(provider.stream_calls.load(Ordering::SeqCst), 1);
        assert!(prepared.deferred_failure_output.is_none());
        assert!(prepared.deferred_terminal.is_none());
        assert_eq!(
            sink.events
                .iter()
                .filter(|event| matches!(
                    event,
                    ChatTurnEvent::Output(ChatOutput::Notice { text, .. })
                        if text.contains("made no meaningful progress")
                ))
                .count(),
            1,
            "one watchdog expiry produces one typed presentation notice"
        );
        assert!(
            !sink.events.iter().any(|event| matches!(
                event,
                ChatTurnEvent::Output(ChatOutput::StreamDone { .. }) | ChatTurnEvent::Terminal(_)
            )),
            "a timed-out stream cannot publish done or a deferred terminal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn w207_cancellation_terminates_the_admitted_stream_without_a_lingering_effect() {
        let provider = std::sync::Arc::new(W207DelayedEventProvider::new(vec![W207StreamStep {
            delay: Duration::from_secs(3_600),
            payload: w207_visible("must never arrive", false),
        }]));
        let cancellation = ChatTurnCancellation::default();
        let turn = tokio::spawn(run_w207_stream_turn(
            std::sync::Arc::clone(&provider),
            cancellation.clone(),
        ));
        provider.wait_for_admission().await;
        cancellation.close();
        tokio::task::yield_now().await;
        let (result, prepared, sink) = turn.await.expect("join W207 cancelled stream turn");

        assert!(
            result.is_err(),
            "closing the shared turn gate terminates the stream"
        );
        assert_eq!(provider.stream_calls.load(Ordering::SeqCst), 1);
        assert!(prepared.deferred_failure_output.is_none());
        assert!(prepared.deferred_terminal.is_none());
        assert!(
            !sink.events.iter().any(|event| matches!(
                event,
                ChatTurnEvent::Output(ChatOutput::StreamDone { .. }) | ChatTurnEvent::Terminal(_)
            )),
            "the cancelled provider effect leaves no completion after its task returns"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn w207_post_reply_review_stall_times_out_before_done_or_terminal_success() {
        let provider = std::sync::Arc::new(W207PostReplyReviewProvider::new());
        let mut turn = tokio::spawn(run_w207_post_reply_review_turn(
            std::sync::Arc::clone(&provider),
            ChatTurnCancellation::default(),
        ));
        tokio::select! {
            () = provider.wait_for_review_call() => {}
            _ = &mut turn => panic!("the prepared turn completed before reaching its post-reply review call"),
        }
        tokio::time::advance(crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT).await;
        tokio::task::yield_now().await;
        let (result, prepared, sink) = turn.await.expect("join W207 post-reply review turn");

        let error = result.expect_err("a stalled post-reply review call must time out the turn");
        assert!(
            error
                .downcast_ref::<crate::cli::chat_turn_watchdog::TurnSilenceTimeout>()
                .is_some(),
            "the post-reply review stall keeps the typed silence outcome"
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            2,
            "one foreground dispatch and one review-stage provider call are admitted"
        );
        assert!(prepared.deferred_failure_output.is_none());
        assert!(prepared.deferred_terminal.is_none());
        assert_eq!(
            sink.events
                .iter()
                .filter(|event| matches!(
                    event,
                    ChatTurnEvent::Output(ChatOutput::Notice { text, .. })
                        if text.contains("made no meaningful progress")
                ))
                .count(),
            1,
            "post-reply review expiry emits its typed presentation notice once"
        );
        assert!(
            !sink.events.iter().any(|event| matches!(
                event,
                ChatTurnEvent::Output(ChatOutput::StreamDone { .. }) | ChatTurnEvent::Terminal(_)
            )),
            "a post-reply review timeout cannot leak done or a successful terminal"
        );
    }

    #[test]
    fn admitted_local_chat_identity_is_domain_separated_and_length_delimited() {
        let identity = admitted_local_chat_identity("local-turn-a").expect("build identity");
        assert!(identity.starts_with(LOCAL_CHAT_WAL_SESSION_DOMAIN));
        let prefix_len = LOCAL_CHAT_WAL_SESSION_DOMAIN.len();
        let encoded_len = u64::from_be_bytes(
            identity[prefix_len..prefix_len + std::mem::size_of::<u64>()]
                .try_into()
                .expect("identity has length prefix"),
        );
        assert_eq!(encoded_len, "local-turn-a".len() as u64);
        assert_ne!(
            identity,
            admitted_local_chat_identity("local-turn-b").expect("build distinct identity"),
            "distinct admitted local session labels never share a canonical identity tuple"
        );
    }

    #[test]
    fn incognito_never_mints_a_wal_session_or_changes_its_zero_anchor() {
        assert_eq!(
            wal_session_for_admitted_local_turn(
                Path::new("a home that need not exist for incognito"),
                "incognito-logical-label-is-not-an-authority",
                true,
            )
            .expect("incognito bypasses WAL key lookup"),
            None,
        );
        let payload = br#"{"incognito":true}"#;
        let anchor = crate::wal::make_header(EVENT_TYPE_INCOGNITO_TURN, payload);
        assert_eq!(
            anchor.session_id,
            crate::wal::SessionId::ZERO,
            "the metadata-only incognito anchor remains intentionally unattributed"
        );
    }

    #[test]
    fn prepared_turn_terminal_mirror_preserves_seeded_context_before_final_receipt_and_terminal() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build retained-context test runtime");
        // CWD, like environment variables, is process-global. Acquire the
        // crate-wide process-state lock before the guard and retain it until
        // the async turn returns and the guard has restored the original CWD.
        let _environment = crate::test_env::lock();
        runtime.block_on(async {
            let fixture = tempfile::tempdir().expect("create retained-context fixture");
            let home = fixture.path().join("home");
            let repo = fixture.path().join("repo");
            let other_home = fixture.path().join("other-home");
            let other_repo = fixture.path().join("other-repo");
            std::fs::create_dir_all(&home).expect("create retained-context home");
            let instance_paths = seed_pipeline_repo_context(&home, &repo);
            std::fs::create_dir_all(&other_home).expect("create cross-root home");
            let other_source = other_repo.join("src/cross_root_marker.rs");
            std::fs::create_dir_all(other_source.parent().expect("cross-root source parent"))
                .expect("create cross-root source directory");
            std::fs::write(&other_source, "pub fn cross_root_marker() {}\n")
                .expect("write cross-root marker source");
            let other_paths = InstancePaths::for_home(&other_home);
            let other_root = crate::code_map::CanonicalRepoRoot::discover(&other_repo)
                .expect("discover separately seeded cross-root repository");
            crate::code_map::rebuild_snapshot(
                &other_root,
                &other_paths.code_map,
                crate::code_map::RebuildOptions::default(),
            )
            .expect("persist separately seeded cross-root snapshot");
            let _cwd = PipelineCwdGuard::enter(&repo);
            let selected_config_path = home.join("freedom.yaml");
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).expect("create retained-context WAL directory");
            crate::consent::grant(&home, ProviderKind::ClaudeCli)
                .expect("grant fixture provider consent");

            let mut config = FreedomConfig {
                provider_kind: Some(ProviderKind::ClaudeCli),
                provider_binary: Some("claude".to_owned()),
                provider_model: Some("retained-context-retry-model".to_owned()),
                autonomy: crate::permissions::AutonomyLevel::Full,
                review_gate_enabled: false,
                steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
                ..Default::default()
            };
            config.council.disabled = Some(true);
            config.memory.recall_shortcut = false;
            config.code_map.auto_context_max_files = 5;
            config.refusal_recovery.enabled = true;
            config.refusal_recovery.max_attempts = 1;

            let mut prepared = PreparedChatTurn {
                input: ChatTurnInput {
                    message: Some("find retained_context_marker".to_owned()),
                    model: Some("retained-context-retry-model".to_owned()),
                    skill: None,
                    system: None,
                    attach: Vec::new(),
                    repository_root: None,
                    edit: false,
                    resume_from: None,
                    incognito: false,
                    loop_mode: false,
                    iterations: None,
                    until: Vec::new(),
                    stream: false,
                    temperature: None,
                    top_p: None,
                    sampling_seed: None,
                },
                preparation: ChatTurnPreparation {
                    config,
                    ephemeral_consent: crate::consent::EphemeralConsent::default(),
                    stream_control_token: None,
                    typed_gui_controls: false,
                    replay_context: None, replay_selected_skill: None,
                    reasoning_display: false,
                    cancellation: ChatTurnCancellation::default(),
                    session_canary: std::sync::Arc::new(
                        crate::security::injection_tracker::CanaryToken::generate()
                            .expect("mint retained-context session canary"),
                    ),
                    instance_paths,
                    first_tour_home: home.clone(),
                    selected_config_path,
                    prompt: "find retained_context_marker".to_owned(),
                    current_session_id: "retained-context-retry-regression".to_owned(), wal_session: None,
                    chat_ts_unix: 1_725_000_002,
                    mcp_servers: crate::mcp::McpServers::default(),
                    scoped_mcp_servers: Vec::new(),
                    tweaks: crate::tweaks::Tweaks::default(),
                    profile_extensions:
                        crate::profile::extension_registry::TypedExtensionRegistry::default(),
                    slash_skill_name: None,
                    explicit_route_requested: false,
                    normal_chat_role: None,
                },
                abliterated_loader: None,
                deferred_failure_output: None,
                deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
            };
            let segment_path = wal_dir.join("retained-context-retry-000001.wal");
            let (writer, writer_completion) = crate::wal::writer::spawn_for_home_with_completion(
                segment_path.clone(),
                home.clone(),
            )
            .expect("spawn retained-context WAL writer");
            let provider = RetainedContextRetryProvider::default();
            let mut sink = CollectingSink::default();

            let deferred_output =
                run_prepared_chat_turn(&mut prepared, &provider, &writer, &segment_path, &mut sink)
                    .await
                    .expect("prepared turn accepts the recovered provider reply");

            assert!(
                deferred_output.is_none(),
                "non-stream recovery has no done line"
            );
            {
                let requests = provider.requests.lock().expect("read captured requests");
                assert_eq!(
                    requests.len(),
                    1,
                    "the W206 terminal mirror must prevent a retry after the initial refusal"
                );
                for request in requests.iter() {
                    let system = request.system.as_deref().expect("retained request system");
                    assert!(
                        system.contains("retained_context_marker"),
                        "every successful-route request retains the seeded code-map context: {system}"
                    );
                    assert!(
                        !system.contains("cross_root_marker"),
                        "the selected root must not absorb a separately seeded root: {system}"
                    );
                }
                let initial_system = requests[0]
                    .system
                    .as_deref()
                    .expect("initial retained request system");
                assert_eq!(initial_system.matches("skills:registry:").count(), 1);
            }
            let visible_mirror = sink.events.iter().find_map(|event| match event {
                ChatTurnEvent::Output(ChatOutput::HumanStdout { text }) => Some(text.clone()),
                _ => None,
            }).expect("terminal mirror must replace the refused response");
            assert_ne!(visible_mirror, "recovered reply after the truthful retry");
            assert!(
                !sink
                    .events
                    .iter()
                    .any(|event| matches!(event, ChatTurnEvent::Terminal(_))),
                "the final receipt exists before, never after, caller-owned terminal release"
            );
            assert!(prepared.deferred_terminal.is_some());

            drop(writer);
            writer_completion
                .wait()
                .await
                .expect("drain retained-context WAL writer");
            let wal = std::fs::read(&segment_path).expect("read retained-context WAL");
            let mut retained = Vec::new();
            let mut final_receipts = Vec::new();
            crate::wal::scan::for_each_frame(&wal, |offset, decoded| {
                if decoded.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                    && decoded.header.event_subtype
                        == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8
                {
                    let payload: serde_json::Value = serde_json::from_slice(decoded.payload)
                        .expect("decode retained-context extended WAL payload");
                    match payload["status"].as_str() {
                        Some("retained_in_provider_request") => retained.push((offset, payload)),
                        Some("final_reply_prepared") => final_receipts.push((offset, payload)),
                        _ => {}
                    }
                }
                Ok(())
            })
            .expect("scan retained-context WAL frames");
            assert_eq!(retained.len(), 1, "one retained request audit is bound to this turn");
            assert_eq!(final_receipts.len(), 1, "one final result receipt is bound to this turn");
            let (retained_offset, retained_payload) = &retained[0];
            let (final_offset, final_payload) = &final_receipts[0];
            assert!(
                retained_offset < final_offset,
                "the durable retained-request audit precedes the final result receipt"
            );
            for field in [
                "root_identity_hash_sha256",
                "index_generation",
                "graph_generation",
                "context_hash_sha256",
                "binding_sha256",
            ] {
                assert_eq!(
                    retained_payload[field], final_payload[field],
                    "the final result must retain the exact {field} provenance"
                );
            }
            assert_eq!(final_payload["completion_kind"], "chat_terminal");
            assert_eq!(
                final_payload["final_reply_hash_xxh3"],
                xxhash_rust::xxh3::xxh3_64(visible_mirror.as_bytes())
            );
            assert_eq!(final_payload["final_reply_bytes"], visible_mirror.len());
            let mirrors = refusal_mirror_receipts(&wal);
            assert_eq!(mirrors.len(), 1, "one typed terminal mirror receipt is required");
            assert!(mirrors[0]["refusal_class"].is_string());
            assert!(mirrors[0]["source"].is_string());
            assert!(mirrors[0]["terminal_condition"].is_string());
            emit_terminal(
                &mut sink,
                prepared
                    .deferred_terminal
                    .take()
                    .expect("successful route leaves terminal for caller release"),
            )
            .expect("release terminal after durable final binding");
            assert!(matches!(
                sink.events.last(),
                Some(ChatTurnEvent::Terminal(ChatTurnTerminal::Complete { provider, model, .. }))
                    if provider == "retained-context-retry-mock"
                        && model == "retained-context-retry-model"
            ));
        });
    }

    #[test]
    fn prepared_turn_terminal_mirror_blocks_retry_and_local_shadow_after_authorized_snapshot() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build W137 retained-session runtime");
        let _environment = crate::test_env::lock();
        runtime.block_on(async {
            let fixture = tempfile::tempdir().expect("create W137 retained-session fixture");
            let home = fixture.path().join("home");
            let repo = fixture.path().join("repo");
            std::fs::create_dir_all(&home).expect("create W137 home");
            let instance_paths = seed_pipeline_repo_context(&home, &repo);
            let _cwd = PipelineCwdGuard::enter(&repo);
            let selected_config_path = home.join("freedom.yaml");
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).expect("create W137 WAL directory");
            crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key"))
                .expect("initialize W137 WAL key");
            crate::skills::authority::initialize_authority_key_for_test(&home)
                .expect("initialize W137 authority key");
            crate::consent::grant(&home, ProviderKind::ClaudeCli)
                .expect("grant W137 fixture provider consent");

            let mut config = FreedomConfig {
                provider_kind: Some(ProviderKind::ClaudeCli),
                provider_binary: Some("claude".to_owned()),
                provider_model: Some("w137-caller-model".to_owned()),
                autonomy: crate::permissions::AutonomyLevel::Full,
                review_gate_enabled: false,
                steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
                ..Default::default()
            };
            config.council.disabled = Some(true);
            config.memory.recall_shortcut = false;
            config.code_map.auto_context_max_files = 5;
            config.refusal_recovery.enabled = true;
            config.refusal_recovery.max_attempts = 1;
            config.refusal_recovery.abliterated_fallback_enabled = true;
            config.refusal_recovery.abliterated_model = Some("fixture-local-abliterated-model".to_owned());
            config.refusal_recovery.teacher_escalation_enabled = false;
            std::fs::write(&selected_config_path, serde_yaml::to_string(&config).expect("serialize W137 config"))
                .expect("write W137 config");
            let authority_reload = std::sync::Arc::new(crate::config::reload::ReloadController::new(
                config.clone(),
                selected_config_path.clone(),
            ));

            w137_write_installed_skill(
                &home,
                W137_SELECTED_SKILL_ID,
                &w137_skill_manifest(
                    "W137 selected A registry description",
                    W137_SELECTED_A_BODY,
                    "w137-a-model",
                    "high",
                ),
            );
            w137_record_install_incarnation(&home, W137_SELECTED_SKILL_ID);
            w137_publish_authority(
                &home,
                W137_SELECTED_SKILL_ID,
                authority_reload.as_ref(),
                crate::skills::authority::SkillAuthorityState::Active,
                None,
            );
            w137_write_installed_skill(
                &home,
                "w137-disabled",
                "id: w137-disabled\ndescription: W137 disabled registry description\nsystem_prompt: W137_DISABLED_APPROVED_CANDIDATE_BODY\nenabled: false\n",
            );
            w137_write_installed_skill(
                &home,
                "w137-rejected",
                "id: w137-rejected\ndescription: W137 rejected registry description\nsystem_prompt: W137_AUTHORITY_REJECTED_CANDIDATE_BODY\n",
            );
            w137_record_install_incarnation(&home, "w137-rejected");
            w137_publish_authority(
                &home,
                "w137-rejected",
                authority_reload.as_ref(),
                crate::skills::authority::SkillAuthorityState::Inactive,
                Some("W137 fixture operator rejection"),
            );

            let local_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
            let loader = std::sync::Arc::new(RetainedContextFallbackLoader {
                local_requests: std::sync::Arc::clone(&local_requests),
            });
            let mut prepared = PreparedChatTurn {
                input: ChatTurnInput { message: Some("w137-retained-session".to_owned()), model: Some("w137-caller-model".to_owned()), skill: Some(W137_SELECTED_SKILL_ID.to_owned()), system: None, attach: Vec::new(), repository_root: None, edit: false, resume_from: None, incognito: false, loop_mode: false, iterations: None, until: Vec::new(), stream: false, temperature: None, top_p: None, sampling_seed: None },
                preparation: ChatTurnPreparation { config: config.clone(), ephemeral_consent: crate::consent::EphemeralConsent::default(), stream_control_token: None, typed_gui_controls: false, replay_context: None, replay_selected_skill: None, reasoning_display: false, cancellation: ChatTurnCancellation::default(), session_canary: std::sync::Arc::new(crate::security::injection_tracker::CanaryToken::generate().expect("mint W137 session canary")), instance_paths: instance_paths.clone(), first_tour_home: home.clone(), selected_config_path: selected_config_path.clone(), prompt: "w137-retained-session".to_owned(), current_session_id: "w137-retained-A".to_owned(), wal_session: None, chat_ts_unix: 1_725_000_137, mcp_servers: crate::mcp::McpServers::default(), scoped_mcp_servers: Vec::new(), tweaks: crate::tweaks::Tweaks::default(), profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry::default(), slash_skill_name: None, explicit_route_requested: true, normal_chat_role: None },
                abliterated_loader: Some(loader), deferred_failure_output: None, deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
            };
            let segment_path = wal_dir.join("w137-retained-a-000001.wal");
            let (writer, completion) = crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home.clone())
                .expect("spawn W137 A WAL writer");
            let provider = W137SnapshotPublishingFallbackCloudProvider {
                home: home.clone(), reload: std::sync::Arc::clone(&authority_reload), requests: Mutex::new(Vec::new()), published_b: std::sync::atomic::AtomicBool::new(false),
            };
            let mut sink = CollectingSink::default();
            run_prepared_chat_turn(&mut prepared, &provider, &writer, &segment_path, &mut sink)
                .await
                .expect("W137 A turn recovers through local shadow");
            assert!(provider.published_b.load(Ordering::SeqCst), "the first refused request must publish authorized B before recovery");

            let registry_a = {
                let cloud = provider.requests.lock().expect("read W137 cloud requests");
                assert_eq!(cloud.len(), 1, "the W206 terminal mirror must prevent a retry after the initial refusal");
                for request in cloud.iter() {
                    let system = request.system.as_deref().expect("W137 cloud request system");
                    assert!(system.contains(W137_SELECTED_A_BODY), "the started session retains selected A body");
                    assert!(!system.contains(W137_SELECTED_B_BODY), "B cannot enter an already-composed A recovery request");
                    assert!(!system.contains(W137_DISABLED_BODY), "disabled candidate must never inject");
                    assert!(!system.contains(W137_REJECTED_BODY), "authority-rejected candidate must never inject");
                    assert_eq!(request.model.as_deref(), Some("w137-a-model"), "selected A route model survives truthful recovery");
                    assert_eq!(request.thinking_budget, Some(16_384), "selected A effort survives truthful recovery");
                }
                let first = cloud[0].system.as_deref().expect("initial W137 cloud system");
                let registry_a = retained_skill_registry_context(first);
                assert!(registry_a.contains("W137 selected A registry description"));
                registry_a
            };
            {
                let local = local_requests.lock().expect("read W137 local-shadow request");
                assert!(local.is_empty(), "the terminal mirror must not open a local-shadow provider leaf");
            }
            drop(writer);
            completion.wait().await.expect("drain W137 A WAL");
            let wal = std::fs::read(&segment_path).expect("read W137 A WAL");
            let mirrors = refusal_mirror_receipts(&wal);
            assert_eq!(mirrors.len(), 1, "W137 A refusal must commit one terminal mirror receipt");
            assert!(mirrors[0]["terminal_condition"].is_string());

            let mut fresh = PreparedChatTurn {
                input: ChatTurnInput { message: Some("w137-retained-session".to_owned()), model: Some("w137-caller-model".to_owned()), skill: Some(W137_SELECTED_SKILL_ID.to_owned()), system: None, attach: Vec::new(), repository_root: None, edit: false, resume_from: None, incognito: false, loop_mode: false, iterations: None, until: Vec::new(), stream: false, temperature: None, top_p: None, sampling_seed: None },
                preparation: ChatTurnPreparation { config, ephemeral_consent: crate::consent::EphemeralConsent::default(), stream_control_token: None, typed_gui_controls: false, replay_context: None, replay_selected_skill: None, reasoning_display: false, cancellation: ChatTurnCancellation::default(), session_canary: std::sync::Arc::new(crate::security::injection_tracker::CanaryToken::generate().expect("mint W137 fresh-session canary")), instance_paths, first_tour_home: home.clone(), selected_config_path, prompt: "w137-retained-session".to_owned(), current_session_id: "w137-retained-B".to_owned(), wal_session: None, chat_ts_unix: 1_725_000_138, mcp_servers: crate::mcp::McpServers::default(), scoped_mcp_servers: Vec::new(), tweaks: crate::tweaks::Tweaks::default(), profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry::default(), slash_skill_name: None, explicit_route_requested: true, normal_chat_role: None },
                abliterated_loader: None, deferred_failure_output: None, deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
            };
            let fresh_segment = wal_dir.join("w137-retained-b-000001.wal");
            let (fresh_writer, fresh_completion) = crate::wal::writer::spawn_for_home_with_completion(fresh_segment.clone(), home.clone())
                .expect("spawn W137 B WAL writer");
            let fresh_provider = W137FreshSessionProvider::default();
            let mut fresh_sink = CollectingSink::default();
            run_prepared_chat_turn(&mut fresh, &fresh_provider, &fresh_writer, &fresh_segment, &mut fresh_sink)
                .await
                .expect("fresh W137 session accepts authorized B");
            let fresh_requests = fresh_provider.requests.lock().expect("read W137 fresh-session request");
            assert_eq!(fresh_requests.len(), 1);
            let fresh_request = &fresh_requests[0];
            let fresh_system = fresh_request.system.as_deref().expect("fresh W137 system");
            assert!(fresh_system.contains(W137_SELECTED_B_BODY), "a later session must resolve B body");
            assert!(!fresh_system.contains(W137_SELECTED_A_BODY), "a later session must not reuse A body");
            assert_eq!(fresh_request.model.as_deref(), Some("w137-b-model"), "a later session must resolve B model");
            assert_eq!(fresh_request.thinking_budget, Some(1_024), "a later session must resolve B effort");
            let registry_b = retained_skill_registry_context(fresh_system);
            assert!(registry_b.contains("W137 selected B registry description"));
            assert_ne!(registry_b, registry_a, "a later session must acquire the newly authorized B registry generation");
            drop(fresh_requests);
            drop(fresh_writer);
            fresh_completion.wait().await.expect("drain W137 B WAL");
        });
    }

    #[test]
    fn prepared_turn_terminal_mirror_blocks_truthful_refusal_and_local_shadow_final_result() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build fallback chat runtime");
        let _environment = crate::test_env::lock();
        runtime.block_on(async {
            let fixture = tempfile::tempdir().expect("create fallback chat fixture");
            let home = fixture.path().join("home");
            let repo = fixture.path().join("repo");
            std::fs::create_dir_all(&home).expect("create fallback chat home");
            let instance_paths = seed_pipeline_repo_context(&home, &repo);
            let _cwd = PipelineCwdGuard::enter(&repo);
            crate::consent::grant(&home, ProviderKind::ClaudeCli).expect("grant fallback chat consent");
            let mut config = FreedomConfig { provider_kind: Some(ProviderKind::ClaudeCli), provider_binary: Some("claude".to_owned()), provider_model: Some("retained-context-fallback-model".to_owned()), autonomy: crate::permissions::AutonomyLevel::Full, review_gate_enabled: false, steps_completed: vec![1,2,3,4,5,6,7], ..Default::default() };
            config.council.disabled = Some(true);
            config.memory.recall_shortcut = false;
            config.code_map.auto_context_max_files = 5;
            config.refusal_recovery.enabled = true;
            config.refusal_recovery.max_attempts = 1;
            config.refusal_recovery.abliterated_fallback_enabled = true;
            config.refusal_recovery.abliterated_model = Some("fixture-local-abliterated-model".to_owned());
            config.refusal_recovery.teacher_escalation_enabled = false;
            let local_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
            let loader = std::sync::Arc::new(RetainedContextFallbackLoader { local_requests: std::sync::Arc::clone(&local_requests) });
            let selected_config_path = home.join("freedom.yaml");
            let mut prepared = PreparedChatTurn {
                input: ChatTurnInput { message: Some("find retained_context_marker".to_owned()), model: Some("retained-context-fallback-model".to_owned()), skill: None, system: None, attach: Vec::new(), repository_root: None, edit: false, resume_from: None, incognito: false, loop_mode: false, iterations: None, until: Vec::new(), stream: false, temperature: None, top_p: None, sampling_seed: None },
                preparation: ChatTurnPreparation { config, ephemeral_consent: crate::consent::EphemeralConsent::default(), stream_control_token: None, typed_gui_controls: false, replay_context: None, replay_selected_skill: None, reasoning_display: false, cancellation: ChatTurnCancellation::default(), session_canary: std::sync::Arc::new(crate::security::injection_tracker::CanaryToken::generate().expect("mint fallback chat canary")), instance_paths, first_tour_home: home.clone(), selected_config_path, prompt: "find retained_context_marker".to_owned(), current_session_id: "retained-context-fallback-regression".to_owned(), wal_session: None, chat_ts_unix: 1_725_000_004, mcp_servers: crate::mcp::McpServers::default(), scoped_mcp_servers: Vec::new(), tweaks: crate::tweaks::Tweaks::default(), profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry::default(), slash_skill_name: None, explicit_route_requested: false, normal_chat_role: None },
                abliterated_loader: Some(loader), deferred_failure_output: None, deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
            };
            let wal_dir = home.join("wal"); std::fs::create_dir_all(&wal_dir).expect("create fallback chat WAL directory");
            let segment_path = wal_dir.join("fallback-chat-000001.wal");
            let (writer, completion) = crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home.clone()).expect("spawn fallback chat WAL");
            let provider = RetainedContextFallbackCloudProvider::default();
            let mut sink = CollectingSink::default();
            run_prepared_chat_turn(&mut prepared, &provider, &writer, &segment_path, &mut sink).await.expect("fallback chat route accepts recovered final");
            let visible_mirror = sink.events.iter().find_map(|event| match event {
                ChatTurnEvent::Output(ChatOutput::HumanStdout { text }) => Some(text.clone()),
                _ => None,
            }).expect("terminal mirror must replace the refused response");
            assert_ne!(visible_mirror, "local shadow draft");
            assert!(!sink.events.iter().any(|event| matches!(event, ChatTurnEvent::Terminal(_))), "caller terminal remains deferred until after durable final receipt");
            {
                let requests = provider.requests.lock().expect("read fallback cloud requests");
                assert_eq!(
                    requests.len(),
                    1,
                    "the W206 terminal mirror must prevent a truthful retry after the initial refusal"
                );
                let initial = &requests[0];
                assert_eq!(initial.prompt, "find retained_context_marker");
                assert_eq!(initial.model.as_deref(), Some("retained-context-fallback-model"));
                let initial_system = initial.system.as_deref().expect("initial fallback cloud system");
                assert!(initial_system.contains("retained_context_marker"));
                assert!(initial_system.contains(crate::security::operator_sovereignty::OPERATOR_SOVEREIGNTY_DIRECTIVE));
                assert_eq!(initial_system.matches("skills:registry:").count(), 1);
            }
            {
                let local = local_requests.lock().expect("read fallback local requests");
                assert!(local.is_empty(), "the terminal mirror must not open a local-shadow provider leaf");
            }
            drop(writer);
            completion.wait().await.expect("drain fallback chat WAL");
            let wal = std::fs::read(&segment_path).expect("read fallback chat WAL");
            let mut retained = Vec::new(); let mut final_receipts = Vec::new();
            crate::wal::scan::for_each_frame(&wal, |offset, frame| { if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED && frame.header.event_subtype == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8 { let payload: serde_json::Value = serde_json::from_slice(frame.payload).expect("decode fallback chat payload"); match payload["status"].as_str() { Some("retained_in_provider_request") => retained.push((offset,payload)), Some("final_reply_prepared") => final_receipts.push((offset,payload)), _ => {} } } Ok(()) }).expect("scan fallback chat WAL");
            assert_eq!(retained.len(), 1); assert_eq!(final_receipts.len(), 1); assert!(retained[0].0 < final_receipts[0].0);
            for field in ["root_identity_hash_sha256", "index_generation", "graph_generation", "context_hash_sha256", "binding_sha256"] { assert_eq!(retained[0].1[field], final_receipts[0].1[field], "fallback final preserves {field}"); }
            assert_eq!(final_receipts[0].1["completion_kind"], "chat_terminal");
            assert_eq!(final_receipts[0].1["final_reply_hash_xxh3"], xxhash_rust::xxh3::xxh3_64(visible_mirror.as_bytes()));
            assert_eq!(final_receipts[0].1["final_reply_bytes"], visible_mirror.len());
            let mirrors = refusal_mirror_receipts(&wal);
            assert_eq!(mirrors.len(), 1, "one typed terminal mirror receipt is required");
            assert!(mirrors[0]["terminal_condition"].is_string());
            emit_terminal(&mut sink, prepared.deferred_terminal.take().expect("deferred terminal after final receipt")).expect("emit fallback chat terminal");
        });
    }

    #[test]
    fn prepared_streaming_terminal_mirror_reports_finalization_error_when_final_binding_append_fails()
     {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build final-binding failure runtime");
        let _environment = crate::test_env::lock();
        runtime.block_on(async {
            let fixture = tempfile::tempdir().expect("create final-binding failure fixture");
            let home = fixture.path().join("home");
            let repo = fixture.path().join("repo");
            std::fs::create_dir_all(&home).expect("create final-binding failure home");
            let instance_paths = seed_pipeline_repo_context(&home, &repo);
            let _cwd = PipelineCwdGuard::enter(&repo);
            let selected_config_path = home.join("freedom.yaml");
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).expect("create final-binding failure WAL directory");
            crate::consent::grant(&home, ProviderKind::ClaudeCli)
                .expect("grant final-binding fixture provider consent");
            let mut config = FreedomConfig {
                provider_kind: Some(ProviderKind::ClaudeCli),
                provider_binary: Some("claude".to_owned()),
                provider_model: Some("retained-context-retry-model".to_owned()),
                autonomy: crate::permissions::AutonomyLevel::Full,
                review_gate_enabled: false,
                steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
                ..Default::default()
            };
            config.council.disabled = Some(true);
            config.memory.recall_shortcut = false;
            config.code_map.auto_context_max_files = 5;
            config.refusal_recovery.enabled = true;
            config.refusal_recovery.max_attempts = 1;
            let prompt = "find retained_context_marker W60_FINAL_BINDING_APPEND_REJECTION_FIXTURE".to_owned();
            let mut prepared = PreparedChatTurn {
                input: ChatTurnInput {
                    message: Some(prompt.clone()), model: Some("retained-context-retry-model".to_owned()),
                    skill: None, system: None, attach: Vec::new(), repository_root: None, edit: false,
                    resume_from: None, incognito: false, loop_mode: false, iterations: None,
                    until: Vec::new(), stream: true, temperature: None, top_p: None, sampling_seed: None,
                },
                preparation: ChatTurnPreparation {
                    config, ephemeral_consent: crate::consent::EphemeralConsent::default(),
                    stream_control_token: Some(Zeroizing::new("final-binding-failure-token".to_owned())),
                    typed_gui_controls: false,
                    replay_context: None, replay_selected_skill: None,
                    reasoning_display: false,
                    cancellation: ChatTurnCancellation::default(),
                    session_canary: std::sync::Arc::new(crate::security::injection_tracker::CanaryToken::generate().expect("mint failure fixture canary")),
                    instance_paths, first_tour_home: home.clone(), selected_config_path, prompt,
                    current_session_id: "final-binding-failure-regression".to_owned(), wal_session: None, chat_ts_unix: 1_725_000_003,
                    mcp_servers: crate::mcp::McpServers::default(), scoped_mcp_servers: Vec::new(),
                    tweaks: crate::tweaks::Tweaks::default(),
                    profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry::default(),
                    slash_skill_name: None, explicit_route_requested: false,
                normal_chat_role: None,
                },
                abliterated_loader: None, deferred_failure_output: None, deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
            };
            let segment_path = wal_dir.join("final-binding-failure-000001.wal");
            let (writer, writer_completion) = crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home.clone())
                .expect("spawn final-binding failure WAL writer");
            let provider = RetainedContextRetryProvider::default();
            let mut sink = CollectingSink::default();
            let error = run_prepared_chat_turn(&mut prepared, &provider, &writer, &segment_path, &mut sink)
                .await
                .expect_err("the final receipt rejection must fail the prepared streaming turn");
            assert!(error.to_string().contains("post_reply_pipeline"));
            assert_eq!(provider.requests.lock().expect("read retained requests").len(), 1);
            assert!(matches!(prepared.deferred_failure_output.as_ref(), Some(ChatOutput::StreamFinalizationError { control_token, .. }) if control_token == "final-binding-failure-token"));
            assert!(prepared.deferred_terminal.is_none(), "no complete terminal is staged after the final receipt failure");
            assert!(!sink.events.iter().any(|event| matches!(event, ChatTurnEvent::Output(ChatOutput::StreamDone { .. }) | ChatTurnEvent::Terminal(_))), "no authenticated done or terminal completion escapes the failed final-binding route");
            drop(writer);
            writer_completion.wait().await.expect("drain failed final-binding WAL");
            let wal = std::fs::read(&segment_path).expect("read failed final-binding WAL");
            assert!(wal.windows(b"retained_in_provider_request".len()).any(|window| window == b"retained_in_provider_request"), "the retained request audit committed before provider success");
            let mirrors = refusal_mirror_receipts(&wal);
            assert_eq!(mirrors.len(), 1, "the final binding failure follows one typed mirror receipt");
            assert!(mirrors[0]["terminal_condition"].is_string());
            assert!(!wal.windows(b"final_reply_prepared".len()).any(|window| window == b"final_reply_prepared"), "the rejected final receipt is never reported as prepared");
        });
    }

    #[tokio::test]
    async fn neutral_engine_keeps_custom_config_for_local_skill_action() {
        let home = tempfile::tempdir().expect("create custom-config action home");
        let home_path = home.path().to_path_buf();
        let selected_config_path = home_path.join("selected-freedom.yaml");
        let default_config_path = home_path.join("freedom.yaml");
        let instance_paths = InstancePaths::new(&home_path, &selected_config_path);
        let wal_dir = home_path.join("wal");
        std::fs::create_dir_all(&wal_dir).expect("create custom-config action WAL directory");
        crate::consent::grant(&home_path, ProviderKind::ClaudeCli)
            .expect("grant the fixture's accepted provider consent");

        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".to_owned()),
            provider_model: Some("neutral-engine-model".to_owned()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        std::fs::write(
            &selected_config_path,
            serde_yaml::to_string(&config).expect("serialize selected config"),
        )
        .expect("write selected config");
        std::fs::write(
            &default_config_path,
            serde_yaml::to_string(&FreedomConfig::default()).expect("serialize default config"),
        )
        .expect("write sibling default config");
        let default_config_before =
            std::fs::read(&default_config_path).expect("read sibling default config before action");

        let mut prepared = PreparedChatTurn {
            input: ChatTurnInput {
                message: Some("/skill disable academic_research".to_owned()),
                model: Some("neutral-engine-model".to_owned()),
                skill: None,
                system: None,
                attach: Vec::new(),
                repository_root: None,
                edit: false,
                resume_from: None,
                incognito: false,
                loop_mode: false,
                iterations: None,
                until: Vec::new(),
                stream: false,
                temperature: None,
                top_p: None,
                sampling_seed: None,
            },
            preparation: ChatTurnPreparation {
                config,
                ephemeral_consent: crate::consent::EphemeralConsent::default(),
                stream_control_token: None,
                typed_gui_controls: false,
                replay_context: None,
                replay_selected_skill: None,
                reasoning_display: false,
                cancellation: ChatTurnCancellation::default(),
                session_canary: std::sync::Arc::new(
                    crate::security::injection_tracker::CanaryToken::generate()
                        .expect("mint session canary"),
                ),
                instance_paths,
                first_tour_home: home_path.clone(),
                selected_config_path: selected_config_path.clone(),
                prompt: "/skill disable academic_research".to_owned(),
                current_session_id: "custom-config-action-regression".to_owned(),
                wal_session: None,
                chat_ts_unix: 1_725_000_001,
                mcp_servers: crate::mcp::McpServers::default(),
                scoped_mcp_servers: Vec::new(),
                tweaks: crate::tweaks::Tweaks::default(),
                profile_extensions:
                    crate::profile::extension_registry::TypedExtensionRegistry::default(),
                slash_skill_name: None,
                explicit_route_requested: false,
                normal_chat_role: None,
            },
            abliterated_loader: None,
            deferred_failure_output: None,
            deferred_terminal: None,
            feedback_eligible_agent_receipt: None,
        };
        let segment_path = wal_dir.join("custom-config-action-000001.wal");
        let (writer, writer_completion) =
            crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home_path)
                .expect("spawn caller-owned WAL writer");
        let provider = NeutralEngineProvider::default();
        let mut sink = CollectingSink::default();

        let deferred_output =
            run_prepared_chat_turn(&mut prepared, &provider, &writer, &segment_path, &mut sink)
                .await
                .expect("local skill action accepts the caller-admitted custom config");

        prepared.preparation.cancellation.close();
        drop(writer);
        writer_completion
            .wait()
            .await
            .expect("caller drains the real WAL writer");

        assert!(
            deferred_output.is_none(),
            "local action has no provider completion"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            std::fs::read_to_string(&selected_config_path)
                .expect("read selected config after /skill action")
                .contains("academic_research"),
            "the local action must update the caller-admitted selected config"
        );
        assert_eq!(
            std::fs::read(&default_config_path)
                .expect("read sibling default config after /skill action"),
            default_config_before,
            "the local action must not fall back to the sibling freedom.yaml"
        );
    }

    #[test]
    fn prepared_chat_mcp_turn_threads_requested_policy_to_real_codegraph_child_after_w55_receipt() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build Chat consumer fixture runtime");
        // Environment and CWD select both the parent auto-context root and the
        // real stdio child's root. Keep the process lock until every guard has
        // restored the state it changed.
        let _environment = crate::test_env::lock();
        runtime.block_on(async {
            let fixture = tempfile::tempdir().expect("create Chat consumer fixture");
            let home = fixture.path().join("selected-home");
            let parent_root = fixture.path().join("unmapped-parent-root");
            let child_root = fixture.path().join("indexed-child-root");
            std::fs::create_dir_all(&home).expect("create selected home");
            std::fs::create_dir_all(&parent_root).expect("create unmapped parent root");
            let paths = InstancePaths::for_home(&home);
            crate::mcp::codegraph_server::w59_seed_real_sqlite_root(
                &paths.code_map,
                &child_root,
                "n",
            );
            let database = paths.code_map.canonicalize().expect("canonical real code-map DB");
            let base = crate::mcp::config::McpServerConfig {
                id: "neoth-codegraph".into(),
                description: None,
                command: std::env::current_exe()
                    .expect("test executable")
                    .canonicalize()
                    .expect("canonical test executable")
                    .display()
                    .to_string(),
                args: vec![
                    "mcp".into(),
                    "codegraph-serve".into(),
                    "--db".into(),
                    database.display().to_string(),
                ],
                env: std::collections::HashMap::new(),
                enabled: true,
                allow_tools: Some(
                    crate::mcp::codegraph_server::TOOL_NAMES
                        .iter()
                        .map(|tool| (*tool).to_owned())
                        .collect(),
                ),
                trust_all_tools: false,
                smart_approve: true,
                autonomy_gate: None,
            };
            let servers = crate::mcp::McpServers {
                servers: vec![base.clone()],
                smart_loading: true,
            };
            std::fs::write(
                &paths.mcp_servers,
                serde_yaml::to_string(&servers).expect("serialize real stdio MCP descriptor"),
            )
            .expect("write selected-home mcp_servers.yaml");

            let selected_config_path = home.join("freedom.yaml");
            let mut config = FreedomConfig {
                provider_kind: Some(ProviderKind::ClaudeCli),
                provider_binary: Some("claude".to_owned()),
                provider_model: Some("chat-consumer-mcp-model".to_owned()),
                autonomy: crate::permissions::AutonomyLevel::Full,
                review_gate_enabled: false,
                steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
                ..Default::default()
            };
            config.council.disabled = Some(true);
            config.memory.recall_shortcut = false;
            config.code_map.auto_context_max_files = 1;
            config.code_map.coding_recall_max_files = 1;
            config.code_map.coding_callers_per_symbol = 1;
            config.code_map.coding_summary_token_budget = 256;
            config.code_map.requested_context_max_bfs_depth = 2;
            std::fs::write(
                &selected_config_path,
                serde_yaml::to_string(&config).expect("serialize selected Chat config"),
            )
            .expect("write selected Chat config");
            crate::consent::grant(&home, ProviderKind::ClaudeCli)
                .expect("grant selected-home provider consent");
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).expect("create selected-home WAL directory");
            // Pre-seed the exact home-owned HMAC key which authenticates the
            // receipt and the later tool-loop WAL records.
            std::fs::write(wal_dir.join("hmac.key"), [0x5A_u8; 32])
                .expect("seed selected-home HMAC key");

            let prior_record = std::env::var_os("NEOTH_W56_CHILD_RECORD");
            let prior_child_cwd = std::env::var_os("NEOTH_W59_CHILD_CWD");
            let prior_autoroute = std::env::var_os("NEOTH_MCP_AUTOROUTE");
            let record = home.join("real-child-events.jsonl");
            unsafe {
                std::env::set_var("NEOTH_W56_CHILD_RECORD", &record);
                std::env::set_var("NEOTH_W59_CHILD_CWD", &child_root);
                std::env::set_var("NEOTH_MCP_AUTOROUTE", "1");
            }
            struct RestoreChatConsumerEnv(
                Option<std::ffi::OsString>,
                Option<std::ffi::OsString>,
                Option<std::ffi::OsString>,
            );
            impl Drop for RestoreChatConsumerEnv {
                fn drop(&mut self) {
                    unsafe {
                        match self.0.take() {
                            Some(value) => std::env::set_var("NEOTH_W56_CHILD_RECORD", value),
                            None => std::env::remove_var("NEOTH_W56_CHILD_RECORD"),
                        }
                        match self.1.take() {
                            Some(value) => std::env::set_var("NEOTH_W59_CHILD_CWD", value),
                            None => std::env::remove_var("NEOTH_W59_CHILD_CWD"),
                        }
                        match self.2.take() {
                            Some(value) => std::env::set_var("NEOTH_MCP_AUTOROUTE", value),
                            None => std::env::remove_var("NEOTH_MCP_AUTOROUTE"),
                        }
                    }
                }
            }
            let _restore = RestoreChatConsumerEnv(prior_record, prior_child_cwd, prior_autoroute);
            let _cwd = PipelineCwdGuard::enter(&parent_root);
            let segment_path = wal_dir.join("chat-consumer-000001.wal");
            let (writer, writer_completion) =
                crate::wal::writer::spawn_for_home_with_completion(segment_path.clone(), home.clone())
                    .expect("spawn Chat consumer WAL writer");
            let provider = ChatConsumerMcpProvider::new(segment_path.clone());
            let mut sink = CollectingSink::default();
            let role_policy_reload = std::sync::Arc::new(
                crate::config::reload::ReloadController::new(
                    config.clone(),
                    selected_config_path.clone(),
                ),
            );

            let mut prepared = match crate::cli::chat::prepare_daemon_plain_chat_turn(
                "find leaf_n".to_owned(),
                config,
                selected_config_path,
                home.clone(),
                &provider,
                role_policy_reload,
                ChatTurnCancellation::default(),
                &mut sink,
            )
            .await
            .expect("daemon plain chat preparation accepts the selected instance") {
                ChatPreparationOutcome::Ready(prepared) => prepared,
                ChatPreparationOutcome::Completed => panic!("ordinary Chat input must prepare a provider turn"),
            };
            let deferred = run_prepared_chat_turn(
                &mut prepared,
                &provider,
                &writer,
                &segment_path,
                &mut sink,
            )
            .await
            .expect("prepared Chat turn reaches the real codegraph child");

            assert!(deferred.is_none(), "plain Chat turn has no stream completion");
            assert!(
                provider.first_call_saw_w55_receipt.load(Ordering::SeqCst),
                "the W55 unavailable-context receipt is durable before the first provider/tool effect"
            );
            assert_eq!(
                provider.requests.lock().expect("read captured requests").len(),
                2,
                "the provider emits exactly one real tool call followed by the normal final response"
            );
            assert!(sink.events.iter().any(|event| matches!(
                event,
                ChatTurnEvent::Output(ChatOutput::HumanStdout { text })
                    if text == "final chat consumer response"
            )));
            assert!(prepared.deferred_terminal.is_some());

            drop(writer);
            writer_completion
                .wait()
                .await
                .expect("drain Chat consumer WAL writer before terminal release");
            let wal = std::fs::read(&segment_path).expect("read Chat consumer WAL");
            assert_eq!(
                wal.windows(b"enabled_context_unavailable".len())
                    .filter(|window| *window == b"enabled_context_unavailable")
                    .count(),
                1,
                "one automatic-context unavailable outcome produces one durable receipt"
            );
            assert!(
                wal.windows(b"\"surface\":\"cli\"".len())
                    .any(|window| window == b"\"surface\":\"cli\"")
                    && wal.windows(b"unmapped_root".len())
                        .any(|window| window == b"unmapped_root"),
                "the receipt retains the actual CLI unmapped-root outcome"
            );

            let events: Vec<serde_json::Value> = std::fs::read_to_string(&record)
                .expect("read real stdio child evidence")
                .lines()
                .map(|line| serde_json::from_str(line).expect("decode child event"))
                .collect();
            let startups: Vec<_> = events.iter().filter(|event| event["event"] == "startup").collect();
            let calls: Vec<_> = events.iter().filter(|event| event["event"] == "tools/call").collect();
            assert_eq!(startups.len(), 1, "one real child owns the Chat tool call");
            assert_eq!(calls.len(), 1, "one requested recall reaches the child");
            assert_eq!(calls[0]["name"], "codegraph_recall_v1");
            assert_eq!(calls[0]["arguments"], serde_json::json!({"prompt":"leaf_n","limit":1}));
            let expected = crate::mcp::codegraph_server::effective_builtin_codegraph_server_with_requested_policy(
                &base,
                crate::config::CodeMapImpactPolicy::default(),
                crate::config::RequestedContextPolicy {
                    recall_max_files: 1,
                    callers_per_symbol: 1,
                    summary_token_budget: 256,
                    max_bfs_depth: 2,
                },
            )
            .expect("derive canonical W59 descriptor");
            let observed = serde_json::from_value::<crate::mcp::config::McpServerConfig>(
                startups[0]["descriptor"].clone(),
            )
            .expect("decode complete real-child descriptor");
            assert_eq!(observed, expected, "Chat preserves the exact W59 descriptor and policy trailer");
            emit_terminal(
                &mut sink,
                prepared.deferred_terminal.take().expect("release normal final terminal"),
            )
            .expect("publish terminal after durable completion");
        });
    }
}
