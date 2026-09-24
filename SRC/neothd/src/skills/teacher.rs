//! GOLD-ADAPT-ODY-08 — Teacher escalation.
//!
//! When the operator's self-hosted (local) model fails or replies with low
//! confidence, this module sends the fenced local output to a SOTA cloud
//! teacher model that writes a corrective reply.
//!
//! **Security:** the local model output is serialized as typed
//! `UntrustedContextClass::ModelOutput` data BEFORE it enters the teacher
//! prompt.
//!
//! **Consent:** this is a cloud-egress call. `teacher_escalation_enabled`
//! defaults to `false`; operators opt in explicitly in `freedom.yaml`.
//!
//! **WAL:** emits `0x85 TEACHER_ESCALATION_ATTEMPTED` and
//! `0x86 TEACHER_ESCALATION_COMPLETE` (both immediate-fsync by default —
//! not in the `needs_immediate_sync` deny-list).
//!
//! **SKILL.md:** on success, an inactive correction manifest is written to
//! `~/.neoth/skills/teacher_correction_<xxh3_hex>/skill.yaml`.
//! It remains pending explicit activation for that exact installed generation.
//! The write is best-effort; a disk error is logged and the corrected text is
//! still returned to the caller.

use anyhow::{Context, Result};
use tracing::info;

use crate::wal::events::{
    EVENT_TYPE_TEACHER_ESCALATION_ATTEMPTED, EVENT_TYPE_TEACHER_ESCALATION_COMPLETE,
};
use crate::wal::writer::WalWriterHandle;

#[derive(Debug)]
pub enum TeacherOutcome {
    /// The teacher produced a usable corrective completion.
    Corrected(crate::providers::Completion),
    /// The teacher itself refused. The caller must keep the original visible
    /// response while accounting for this completed attempt.
    Refused(crate::providers::Completion),
    /// The local completion was neither a refusal nor low-confidence.
    NotEscalated,
}

/// Low-confidence phrases emitted by local models when they are uncertain.
/// Kept deliberately conservative — only unambiguous uncertainty markers so
/// a normal response is never false-positively escalated.
///
/// The list covers Qwen3 / Ouro typical hedging phrases observed in practice.
const LOW_CONFIDENCE_MARKERS: &[&str] = &[
    "i'm not sure",
    "i am not sure",
    "i don't know",
    "i do not know",
    "cannot determine",
    "i cannot determine",
    "i'm unable to determine",
    "i am unable to determine",
    "i'm uncertain",
    "i am uncertain",
    "not enough information",
    "insufficient information",
    "i cannot say for certain",
    "i can't say for certain",
    "i lack the information",
    "unsure about",
    "i'm unsure",
    "i am unsure",
];

/// Returns `true` when `text` contains one or more well-known local-model
/// uncertainty phrases (case-insensitive).  Intentionally conservative —
/// only matches hard uncertainty signals, not every hedged phrasing.
pub fn low_confidence_local(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    LOW_CONFIDENCE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn teacher_trigger(
    local_completion: &crate::providers::Completion,
) -> (
    Option<crate::security::refusal_recovery::CompletionRefusalObservation>,
    bool,
) {
    (
        crate::security::refusal_recovery::observe_completion_refusal(local_completion),
        low_confidence_local(&local_completion.text),
    )
}

/// Dispatch the one teacher provider leaf and quarantine its raw completion
/// before any caller can inspect, account for, persist, or turn it into a
/// skill. Keeping this exact leaf separate makes the ordering testable without
/// widening the production teacher-provider selection surface.
#[allow(clippy::too_many_arguments)]
async fn dispatch_teacher_completion(
    teacher: &dyn crate::providers::Provider,
    teacher_req: crate::providers::Request,
    authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
    writer: Option<&WalWriterHandle>,
    provider_name: &str,
    local_hash: &str,
    prompt_hash: &str,
    is_refusal: bool,
    is_low_conf: bool,
    ts: i64,
    session_canary: Option<&crate::security::injection_tracker::CanaryToken>,
    attempt_budget: &mut crate::security::refusal_recovery::RecoveryAttemptBudget,
) -> Result<Option<crate::providers::Completion>> {
    let corrected = match attempt_budget
        .dispatch(|| async {
            // Emit only after the shared gate reserves this provider leaf.
            // Exhausted recovery must not leave a false attempted record.
            emit_wal(
                writer,
                EVENT_TYPE_TEACHER_ESCALATION_ATTEMPTED,
                serde_json::json!({
                    "provider": provider_name,
                    "local_response_hash_xxh3": local_hash,
                    "prompt_hash_xxh3": prompt_hash,
                    "is_refusal": is_refusal,
                    "is_low_confidence": is_low_conf,
                    "ts_unix": ts,
                }),
            )?;
            teacher
                .complete_authorized(teacher_req, authorizer, "teacher.escalation")
                .await
        })
        .await
    {
        crate::security::refusal_recovery::RecoveryDispatch::Completed(completion) => completion,
        crate::security::refusal_recovery::RecoveryDispatch::ProviderError(error) => {
            return Err(error);
        }
        crate::security::refusal_recovery::RecoveryDispatch::Exhausted => return Ok(None),
        crate::security::refusal_recovery::RecoveryDispatch::DeadlineElapsed => {
            anyhow::bail!("turn-wide refusal-recovery deadline elapsed before teacher escalation")
        }
    };

    crate::cli::chat::guard_optional_chat_canary_completion(session_canary, corrected)
        .map(Some)
        .map_err(|error| {
            crate::cli::chat::opaque_chat_post_mint_failure("teacher_escalation", &error)
        })
}

/// Try the SOTA teacher escalation path.
///
/// # Arguments
/// * `local_completion` — the local model's full reply. Provider-native refusal
///   metadata is authoritative even when the text is empty.
/// * `operator_origin` — typed authentication proof from the local CLI or a
///   pinned operator channel. `None` suppresses cloud egress.
/// * `original_prompt` — the operator's enriched prompt sent to the local model.
/// * `system` — system prompt used in the turn, if any.
/// * `provider_name` — `provider.name()` of the original provider (used only
///   for WAL payload; caller must have already verified `is_local_provider`).
/// * `config` — the operator's full `FreedomConfig` (for `from_config_for_teacher`
///   + `teacher_model_override`).
/// * `home` — active instance root used for its model catalog.
/// * `authorizer` — the live per-leaf cost/permission boundary inherited from
///   the calling chat or channel turn.
/// * `writer` — optional WAL writer (absent in unit tests / dry-run callers).
/// * `session_canary` — the optional opaque token rendered into the finalized
///   request. The teacher leaf checks it before it can classify, persist, or
///   write a correction skill.
/// * `ts` — `now_unix() as i64` from the calling turn.
///
/// # Returns
/// * `Ok(TeacherOutcome::Corrected(corrected))` — teacher produced a corrective completion,
///   including its exact provider/model identity, usage and termination.
/// * `Ok(TeacherOutcome::Refused(completion))` — teacher refused; caller keeps
///   the original visible response and accounts for the attempt.
/// * `Ok(TeacherOutcome::NotEscalated)` — local response is neither a refusal
///   nor low-confidence; caller keeps it unchanged.
/// * `Err(e)` — infrastructure failure (e.g. teacher provider construction
///   failed). Best-effort callers should log and continue with the original.
// Keep the exact provider leaf, authorization boundary, audit writer, and
// timestamp visible together; hiding them in a reusable context risks stale
// cost or audit authority crossing turns.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_teacher_escalation(
    local_completion: &crate::providers::Completion,
    operator_origin: Option<crate::security::operator_sovereignty::AuthenticatedOperatorOrigin>,
    original_prompt: &str,
    system: Option<&str>,
    provider_name: &str,
    config: &crate::config::FreedomConfig,
    home: &std::path::Path,
    authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
    writer: Option<&WalWriterHandle>,
    session_canary: Option<&crate::security::injection_tracker::CanaryToken>,
    ts: i64,
    attempt_budget: &mut crate::security::refusal_recovery::RecoveryAttemptBudget,
) -> Result<TeacherOutcome> {
    if operator_origin.is_none() {
        return Ok(TeacherOutcome::NotEscalated);
    }
    let original_request = crate::providers::Request {
        prompt: original_prompt.to_string(),
        system: system.map(str::to_string),
        ..Default::default()
    };
    if crate::security::refusal_abliterated::hard_block_gate(&original_request, writer, ts)
        .is_some()
    {
        return Ok(TeacherOutcome::NotEscalated);
    }
    let local_response = &local_completion.text;

    // ── Trigger gate ──────────────────────────────────────────────────────
    // Only escalate when the local completion is a provider-native/textual
    // refusal OR its visible response is low-confidence.
    // Pure-local provider check is the CALLER's responsibility (chat.rs /
    // serve_pipeline.rs guard `is_local_provider(provider.name())`).
    let (refusal_observation, is_low_conf) = teacher_trigger(local_completion);
    let is_refusal = refusal_observation.is_some();
    if !is_refusal && !is_low_conf {
        return Ok(TeacherOutcome::NotEscalated);
    }

    // ── Build hashes for WAL audit ─────────────────────────────────────────
    let local_hash = format!(
        "{:016x}",
        refusal_observation.map_or_else(
            || xxhash_rust::xxh3::xxh3_64(local_response.as_bytes()),
            |observation| observation.evidence_hash_xxh3(),
        )
    );
    let prompt_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(original_prompt.as_bytes())
    );

    // ── Build the teacher provider ─────────────────────────────────────────
    // from_config_for_teacher returns Err if teacher_provider is local (guard).
    let teacher = crate::providers::from_config_for_teacher_at(config, home).await?;
    let teacher_name = teacher.name();

    // ── ODY-18 anti-injection: fence the local output ─────────────────────
    // MUST happen before the local text enters the teacher's system prompt.
    // The typed class cannot be mistaken for operator-authored instruction.
    let local_context = crate::pipeline::UntrustedContext::new(
        crate::pipeline::UntrustedContextClass::ModelOutput,
        "teacher:local-model-output",
        local_response,
    )
    .render();
    let fenced_local = local_context.as_str();

    // ── Build the teacher request ──────────────────────────────────────────
    // The fenced local output goes into the SYSTEM (operator-controlled path),
    // not the prompt (instruction-following path) — identical to the abliterated
    // continuation pattern in `abliterated::build_continuation_request`.
    let teacher_system = format!(
        "You are a senior expert AI correcting a flawed or incomplete response from a \
         local self-hosted model. The model's output is fenced below with its source label. \
         Read the operator's original request, evaluate where the local model went wrong \
         (refusal, uncertainty, or error), and write the definitive, helpful corrective \
         response directly.\n\nLocal model output:\n{fenced_local}\n{}",
        system
            .map(|s| format!("\n\nOriginal system context:\n{s}"))
            .unwrap_or_default()
    );

    // Resolve an explicit teacher override through the global alias map and
    // the concrete teacher adapter before cost authorization. With no override,
    // bind the already-built teacher's canonical default.
    let teacher_model = crate::providers::resolve_configured_request_model_for_wire(
        config,
        teacher.as_ref(),
        config.refusal_recovery.teacher_model_override.as_deref(),
    )?;

    let teacher_req = crate::providers::Request {
        prompt: original_prompt.to_string(),
        system: Some(teacher_system),
        model: Some(teacher_model),
        ..Default::default()
    };
    // The effective teacher request also contains untrusted local-model output.
    // Re-run the same permanent floor after composing it so a safe operator
    // prompt cannot smuggle hard-blocked content through the local response.
    if crate::security::refusal_abliterated::hard_block_gate(&teacher_req, writer, ts).is_some() {
        return Ok(TeacherOutcome::NotEscalated);
    }

    // ── Call the teacher ────────────────────────────────────────────────────
    let Some(corrected) = dispatch_teacher_completion(
        teacher.as_ref(),
        teacher_req,
        authorizer,
        writer,
        provider_name,
        &local_hash,
        &prompt_hash,
        is_refusal,
        is_low_conf,
        ts,
        session_canary,
        attempt_budget,
    )
    .await?
    else {
        return Ok(TeacherOutcome::NotEscalated);
    };
    let corrected_bytes = corrected.text.len();
    let teacher_refused =
        crate::security::refusal_recovery::observe_completion_refusal(&corrected).is_some();

    if teacher_refused {
        if let Err(e) = emit_wal(
            writer,
            EVENT_TYPE_TEACHER_ESCALATION_COMPLETE,
            serde_json::json!({
                "teacher_provider": teacher_name,
                "corrected_bytes": corrected_bytes,
                "outcome": "teacher_refused",
                "ts_unix": ts,
            }),
        ) {
            tracing::warn!(error = %e, "ODY-08 teacher refusal WAL emit failed");
        }
        info!(
            teacher_provider = teacher_name,
            corrected_bytes, "ODY-08 teacher escalation returned another refusal"
        );
        return Ok(TeacherOutcome::Refused(corrected));
    }

    // ── Write SKILL.md (best-effort) ───────────────────────────────────────
    let skill_id = format!("teacher_correction_{local_hash}");
    if let Err(e) = write_skill_md_off_runtime(home, &skill_id, &corrected.text).await {
        tracing::warn!(
            error = %e,
            skill_id = &skill_id,
            "ODY-08 teacher skill write failed (non-fatal — correction still returned)"
        );
    }

    // ── WAL 0x86: escalation complete ──────────────────────────────────────
    if let Err(e) = emit_wal(
        writer,
        EVENT_TYPE_TEACHER_ESCALATION_COMPLETE,
        serde_json::json!({
            "teacher_provider": teacher_name,
            "corrected_bytes": corrected_bytes,
            "outcome": "corrected",
            "skill_id": &skill_id,
            "ts_unix": ts,
        }),
    ) {
        tracing::warn!(error = %e, "ODY-08 teacher completion WAL emit failed");
    }

    info!(
        teacher_provider = teacher_name,
        corrected_bytes,
        skill_id = &skill_id,
        "ODY-08 teacher escalation complete"
    );

    Ok(TeacherOutcome::Corrected(corrected))
}

/// Root creation, process/file locking, recovery, fsync, and rename are all
/// blocking filesystem work. Keep the complete transaction off Tokio's async
/// worker, including on a single-worker runtime.
async fn write_skill_md_off_runtime(
    home: &std::path::Path,
    skill_id: &str,
    corrected_text: &str,
) -> Result<()> {
    let home = home.to_path_buf();
    let skill_id = skill_id.to_string();
    let corrected_text = corrected_text.to_string();
    run_skill_write_blocking(move || write_skill_md_at(&home, &skill_id, &corrected_text)).await
}

async fn run_skill_write_blocking<F>(write: F) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(write)
        .await
        .context("join teacher skill filesystem transaction")?
}

/// Write the teacher correction as an inactive SKILL.md manifest to
/// `~/.neoth/skills/<skill_id>/skill.yaml`.  Best-effort — the caller logs
/// and continues on failure.
fn write_skill_md_at(home: &std::path::Path, skill_id: &str, corrected_text: &str) -> Result<()> {
    use crate::skills::schema::SkillManifest;

    let manifest = SkillManifest {
        id: skill_id.to_string(),
        description: "Auto-generated correction skill from GOLD-ADAPT-ODY-08 teacher escalation"
            .to_string(),
        version: "1.0.0".to_string(),
        trigger_keywords: vec![],
        system_prompt: corrected_text.to_string(),
        tool_allowlist: vec![],
        author: Some("neoth-teacher-escalation".to_string()),
        tags: vec!["teacher".to_string(), "auto-generated".to_string()],
        homepage: None,
        source: None,
        modes: vec![],
        enabled: false,
        delegate_to: None,
        model: None,
        paths: vec![],
        effort: None,
        loop_trigger: false,
        visibility: Default::default(),
    };

    let yaml = serde_yaml::to_string(&manifest)?;
    let report = crate::skills::creator::write_skill_yaml_audited(
        home,
        &home.join("skills"),
        skill_id,
        &yaml,
        crate::skills::creator::ExistingSkillPolicy::Replace,
        None,
        crate::skills::installer::SkillMutationOrigin::Teacher,
    )?;
    for warning in crate::skills::operator_skill_warnings(&report.warnings) {
        tracing::warn!(skill_id, %warning, "teacher skill committed with durability warning");
    }
    Ok(())
}

/// The pre-call attempted frame is fail-closed; the post-call completion frame
/// is necessarily best-effort because the provider side effect already ran.
fn emit_wal(
    writer: Option<&WalWriterHandle>,
    event_type: u8,
    payload: serde_json::Value,
) -> Result<()> {
    let Some(writer) = writer else {
        return Ok(());
    };
    let payload_bytes = payload.to_string().into_bytes();
    let header = crate::wal::builder::make_header(event_type, &payload_bytes);
    writer.try_append_sync(header, payload_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_native_empty_refusal_triggers_teacher() {
        let completion = crate::providers::Completion {
            text: String::new(),
            termination: crate::providers::ProviderTermination::refused(
                Some("content_filter".into()),
                crate::providers::RefusalOrigin::FinishReason,
                "content_filter",
                None,
            ),
            ..Default::default()
        };

        let (refusal_observation, is_low_confidence) = teacher_trigger(&completion);
        assert!(refusal_observation.is_some());
        assert!(!is_low_confidence);
    }

    #[tokio::test]
    async fn unauthenticated_origin_cannot_trigger_teacher_provider() {
        let completion = crate::providers::Completion {
            text: "I cannot help with that.".to_string(),
            ..Default::default()
        };
        let home = tempfile::tempdir().unwrap();
        let mut attempt_budget =
            crate::security::refusal_recovery::RecoveryAttemptBudget::after_initial_completion(
                &completion,
            );
        let outcome = try_teacher_escalation(
            &completion,
            None,
            "operator request",
            None,
            "local_qwen",
            &crate::config::FreedomConfig::default(),
            home.path(),
            &crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            None,
            None,
            0,
            &mut attempt_budget,
        )
        .await
        .expect("origin gate must stop before provider construction");

        assert!(matches!(outcome, TeacherOutcome::NotEscalated));
    }

    #[test]
    fn low_confidence_local_matches_expected_phrases() {
        assert!(low_confidence_local("I'm not sure about this topic."));
        assert!(low_confidence_local("I do not know the answer."));
        assert!(low_confidence_local(
            "Cannot determine the correct solution."
        ));
        assert!(low_confidence_local("I am uncertain about this claim."));
        assert!(low_confidence_local("Not enough information to proceed."));
        assert!(low_confidence_local("I'm unsure how to handle that."));
    }

    #[test]
    fn low_confidence_local_does_not_match_normal_replies() {
        assert!(!low_confidence_local(
            "Here is the complete implementation you requested."
        ));
        assert!(!low_confidence_local(
            "The answer is 42. Here is the explanation."
        ));
        assert!(!low_confidence_local("def add(a, b): return a + b"));
        assert!(!low_confidence_local(""));
    }

    #[test]
    fn low_confidence_local_is_case_insensitive() {
        assert!(low_confidence_local("I'M NOT SURE about this."));
        assert!(low_confidence_local("I DON'T KNOW."));
        assert!(low_confidence_local("CANNOT DETERMINE."));
    }

    struct LeakingTeacherProvider {
        reply: String,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for LeakingTeacherProvider {
        fn name(&self) -> &'static str {
            "teacher_fixture"
        }

        async fn complete(
            &self,
            _request: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: self.reply.clone(),
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn teacher_leaf_canary_leak_is_opaque_before_correction_persistence() {
        let canary = crate::security::injection_tracker::CanaryToken::generate().unwrap();
        let literal = canary.as_context_literal();
        let leaked = format!("{}\n{}", &literal[..10], &literal[10..]);
        let teacher = LeakingTeacherProvider {
            reply: leaked.clone(),
        };
        let initial = crate::providers::Completion {
            text: "I am not sure.".to_owned(),
            ..Default::default()
        };
        let mut attempt_budget =
            crate::security::refusal_recovery::RecoveryAttemptBudget::after_initial_completion(
                &initial,
            );
        let skill_home = tempfile::tempdir().unwrap();

        let error = dispatch_teacher_completion(
            &teacher,
            crate::providers::Request {
                prompt: "operator request".to_owned(),
                ..Default::default()
            },
            &crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            None,
            "local_fixture",
            "local-hash",
            "prompt-hash",
            false,
            true,
            0,
            Some(&canary),
            &mut attempt_budget,
        )
        .await
        .expect_err("split canary in teacher response must be quarantined");

        let surfaced = format!("{error:#}");
        assert!(surfaced.contains("content quarantined"));
        assert!(!surfaced.contains(literal));
        assert!(!surfaced.contains(&leaked));
        assert!(
            !skill_home.path().join("skills").exists(),
            "the guarded teacher leaf returns before the caller can write a correction skill"
        );
    }

    #[test]
    fn teacher_skill_uses_active_home_and_shared_transactional_writer() {
        let home = tempfile::tempdir().unwrap();
        write_skill_md_at(
            home.path(),
            "teacher_correction_deadbeef",
            "Correct answer.",
        )
        .expect("write teacher skill");

        let expected = home
            .path()
            .join("skills")
            .join("teacher_correction_deadbeef")
            .join("skill.yaml");
        let body = std::fs::read_to_string(expected).unwrap();
        let manifest: crate::skills::schema::SkillManifest = serde_yaml::from_str(&body).unwrap();
        assert_eq!(manifest.id, "teacher_correction_deadbeef");
        assert_eq!(manifest.system_prompt, "Correct answer.");
        assert!(
            !manifest.enabled,
            "teacher-generated skills must await explicit activation"
        );
    }

    #[test]
    fn teacher_skill_explicitly_updates_its_deterministic_id() {
        let home = tempfile::tempdir().unwrap();
        let id = "teacher_correction_deadbeef";
        write_skill_md_at(home.path(), id, "First correction.").unwrap();
        write_skill_md_at(home.path(), id, "Updated correction.").unwrap();

        let body = std::fs::read_to_string(home.path().join("skills").join(id).join("skill.yaml"))
            .unwrap();
        let manifest: crate::skills::schema::SkillManifest = serde_yaml::from_str(&body).unwrap();
        assert_eq!(manifest.system_prompt, "Updated correction.");
    }

    #[test]
    fn blocking_teacher_write_keeps_a_single_tokio_worker_responsive() {
        let home = tempfile::tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
            home.path().parent().unwrap(),
            &skills_dir,
            true,
            "test skills root",
        )
        .unwrap()
        .unwrap();
        let mutation_guard = crate::skills::installer::lock_skill_mutations(&root).unwrap();
        let write_home = home.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let write = tokio::spawn(run_skill_write_blocking(move || {
                let _ = started_tx.send(());
                write_skill_md_at(
                    &write_home,
                    "teacher_correction_contention",
                    "Correction written after the held lock is released.",
                )
            }));

            started_rx.await.unwrap();
            let heartbeat = tokio::spawn(async {
                tokio::task::yield_now().await;
                "async worker remained responsive"
            });
            assert_eq!(heartbeat.await.unwrap(), "async worker remained responsive");
            drop(mutation_guard);
            write.await.unwrap().unwrap();
        });
    }
}
