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
    ProviderRequestBoundary, TurnRouteResolution, build_prompt_bundle,
    context_preload_session_binding, dispatch_provider, emit_chat_notice, emit_chat_output,
    emit_context_preload_notice, emit_retained_code_map_audits, enforce_preflight,
    extract_attachment_contexts, finalize_provider_request, now_unix,
    opaque_chat_post_mint_failure, preserve_code_map_audit_and_writer_failure,
    resolve_chat_turn_route, routing_safe_effective_cap_at, run_post_reply_pipelines,
    skill_route_frame_line,
};
use crate::config::{FreedomConfig, InstancePaths};
use crate::providers::Request;
use crate::wal::events::{EVENT_TYPE_INCOGNITO_TURN, EVENT_TYPE_RAW_TEXT};

/// Request-local admission gate. Closing this gate prevents the next effect
/// boundary from starting; it never implies a durable cross-client cancel.
#[derive(Clone, Default)]
pub(crate) struct ChatTurnCancellation(Arc<AtomicBool>);

impl ChatTurnCancellation {
    pub(crate) fn close(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn check_open(&self, boundary: &'static str) -> Result<()> {
        anyhow::ensure!(
            !self.0.load(Ordering::Acquire),
            "chat turn cancelled before {boundary}"
        );
        Ok(())
    }

    pub(crate) fn pre_tool_use_cancellation(&self) -> crate::hooks::PreToolUseCancellation {
        crate::hooks::PreToolUseCancellation::from_chat_turn(Arc::clone(&self.0))
    }
}

/// Sanitized presentation events. Provider bytes reach this boundary only
/// after the existing framing/canary validation in `cli::chat`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    StreamDone {
        control_token: Option<String>,
        line: String,
    },
    /// Authenticated or sentinel stream frames constructed by the existing
    /// protocol formatter. Provider text never enters this variant.
    StreamFrames {
        frames: String,
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
    },
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
    pub(crate) cancellation: ChatTurnCancellation,
    pub(crate) session_canary: std::sync::Arc<crate::security::injection_tracker::CanaryToken>,
    pub(crate) instance_paths: InstancePaths,
    pub(crate) first_tour_home: PathBuf,
    pub(crate) selected_config_path: PathBuf,
    pub(crate) prompt: String,
    pub(crate) current_session_id: String,
    pub(crate) chat_ts_unix: i64,
    pub(crate) mcp_servers: crate::mcp::McpServers,
    pub(crate) scoped_mcp_servers: Vec<String>,
    pub(crate) tweaks: crate::tweaks::Tweaks,
    pub(crate) profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry,
    pub(crate) slash_skill_name: Option<String>,
    pub(crate) explicit_route_requested: bool,
}
pub(crate) struct PreparedChatTurn {
    pub(crate) input: ChatTurnInput,
    pub(crate) preparation: ChatTurnPreparation,
    pub(crate) deferred_failure_output: Option<ChatOutput>,
    pub(crate) deferred_terminal: Option<ChatTurnTerminal>,
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
    let PreparedChatTurn {
        input,
        preparation:
            ChatTurnPreparation {
                config,
                ephemeral_consent,
                stream_control_token,
                cancellation,
                session_canary,
                instance_paths,
                first_tour_home,
                selected_config_path,
                prompt,
                current_session_id,
                chat_ts_unix,
                mcp_servers,
                scoped_mcp_servers,
                tweaks,
                profile_extensions,
                slash_skill_name,
                explicit_route_requested,
            },
        deferred_failure_output,
        deferred_terminal,
    } = prepared;
    let args = ChatArgs {
        message: input.message.clone(),
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
        let hdr = crate::wal::make_header(EVENT_TYPE_MODE_CHECKPOINT, &payload);
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
    let attachment_contexts =
        match extract_attachment_contexts(&args.attach, config, first_tour_home, writer.clone())
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
        let raw_header = crate::wal::make_header(EVENT_TYPE_RAW_TEXT, prompt.as_bytes());
        // Capture the event_id before the header moves into `append` — the
        // post-reply profile-learning pipeline (B-Konsens 2026-05-17 below)
        // uses this as the trigger anchor for `extract_window`.
        let raw_event_id = raw_header.event_id.0 as i64;
        writer
            .append(raw_header, prompt.as_bytes().to_vec())
            .await
            .context("write RAW_TEXT WAL frame")?;
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
            session_recall,
        },
        PromptBuildOptions {
            slash_skill_name: slash_skill_name.clone(),
            // B22-TWEAKS-MODEL-01 — pre-loaded fail-loud at the chat boundary.
            persona_override_from_tweaks: tweaks.persona_override.clone(),
        },
    )
    .await?;

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
        &config,
        writer,
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
    if let Some((allowed, disallowed)) = agent_tool_policy {
        mcp_tool_scope = mcp_tool_scope.with_agent(allowed, disallowed);
    }
    // Every complete-body post-provider mutator owns the same user-output
    // boundary. Hooks may Block/Replace; block restoration and refusal
    // recovery may replace bytes. Keep the stream internal until all enabled
    // mutators settle, otherwise visible output and the durable body diverge.
    let defer_provider_output = hooks.iter().any(|hook| {
        hook.stage == crate::hooks::HookStage::PostProviderCall && hook.enabled.unwrap_or(true)
    }) || !pending_block_restorations.is_empty()
        || (!args.incognito
            && (config.refusal_recovery.enabled
                || config.refusal_recovery.abliterated_fallback_enabled
                || (config.refusal_recovery.teacher_escalation_enabled
                    && crate::providers::is_local_provider(provider.name()))));

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
        route: chat_route,
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
        effective_cap: request_token_cap,
    } = budgeted;
    if let Err(error) = emit_retained_code_map_audits(
        &writer,
        repo_recall_audit.as_ref(),
        architecture_recall_audit.as_ref(),
        &prompt,
        final_system.as_deref(),
        "cli",
    )
    .await
    {
        drop(writer);
        let audit_error =
            error.context("code-map context audit failed; provider dispatch refused before egress");
        return Err(preserve_code_map_audit_and_writer_failure(audit_error).await);
    }
    // The actual 0x20 intent is emitted centrally for every concrete leaf,
    // after cost/permission approval and immediately before transport dispatch.
    // Carry the old turn-level business fields into those request-bound frames.
    let turn_id = format!("{raw_event_id:016x}");
    let provider_audit_context = crate::providers::cost_authorization::ProviderCallAuditContext {
        source: Some("chat"),
        call_type: Some("chat_provider_round"),
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
    };

    cancellation.check_open("provider dispatch")?;
    let dispatch_output = match dispatch_provider(
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
        defer_provider_output,
        &canary_token,
        cancellation,
        &hooks,
        &once_guard,
        turn_effect_gate.clone(),
        output,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            // The adapter returned after a transport attempt. Its exact commit
            // cannot be disproven here, so recovery classifies it indeterminate
            // and blocks every fallback/new external leaf for this turn.
            return Err(error);
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

    // This is the concrete dispatched completion identity, not a selected
    // config default. Hold it as data until durable post-reply work and the
    // adapter-owned writer drain both succeed.
    let terminal_provider = completion.identity.provider.clone();
    let terminal_model = completion.identity.wire_model.clone();
    let terminal_session_id = current_session_id.clone();
    let stream_control_token_ref = stream_control_token.as_ref().map(|token| token.as_str());
    cancellation.check_open("post-provider external starts")?;
    let post_reply_result = run_post_reply_pipelines(
        completion,
        writer,
        config,
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
        PostReplyStreamPlan {
            control_token: stream_control_token_ref,
            done_line: stream_done_line,
            output_deferred: stream_output_deferred,
            provider_chunk_count: stream_chunk_count,
            limit_tokens: stream_limit_tokens,
        },
        output,
    )
    .await;
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
    *deferred_terminal = Some(ChatTurnTerminal::Complete {
        provider: terminal_provider,
        model: terminal_model,
        session_id: Some(terminal_session_id),
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
                chat_ts_unix: 1_725_000_000,
                mcp_servers: crate::mcp::McpServers::default(),
                scoped_mcp_servers: Vec::new(),
                tweaks: crate::tweaks::Tweaks::default(),
                profile_extensions:
                    crate::profile::extension_registry::TypedExtensionRegistry::default(),
                slash_skill_name: None,
                explicit_route_requested: false,
            },
            deferred_failure_output: None,
            deferred_terminal: None,
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
            Some(ChatTurnTerminal::Complete { provider, model, session_id })
                if provider == "neutral-engine-mock"
                    && model == "neutral-engine-model"
                    && session_id.as_deref() == Some("neutral-engine-regression")
        ));

        drop(writer);
        writer_completion
            .wait()
            .await
            .expect("caller drains the real WAL writer");
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
                chat_ts_unix: 1_725_000_001,
                mcp_servers: crate::mcp::McpServers::default(),
                scoped_mcp_servers: Vec::new(),
                tweaks: crate::tweaks::Tweaks::default(),
                profile_extensions:
                    crate::profile::extension_registry::TypedExtensionRegistry::default(),
                slash_skill_name: None,
                explicit_route_requested: false,
            },
            deferred_failure_output: None,
            deferred_terminal: None,
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
}
