//! GOLD-ADAPT-ODY-08 — Teacher escalation.
//!
//! When the operator's self-hosted (local) model fails or replies with low
//! confidence, this module sends the fenced local output to a SOTA cloud
//! teacher model that writes a corrective reply.
//!
//! **Security:** the local model output is wrapped via
//! `crate::pipeline::wrap_untrusted` (ODY-18) BEFORE it enters the teacher
//! prompt — prompt-injection payloads from a compromised local model cannot
//! escape into the teacher's instruction-following path.
//!
//! **Consent:** this is a cloud-egress call. `teacher_escalation_enabled`
//! defaults to `false`; operators opt in explicitly in `freedom.yaml`.
//!
//! **WAL:** emits `0x85 TEACHER_ESCALATION_ATTEMPTED` and
//! `0x86 TEACHER_ESCALATION_COMPLETE` (both immediate-fsync by default —
//! not in the `needs_immediate_sync` deny-list).
//!
//! **SKILL.md:** on success, a correction manifest is written to
//! `~/.neoth/skills/teacher_correction_<xxh3_hex>/skill.yaml`.
//! The write is best-effort; a disk error is logged and the corrected text
//! is still returned to the caller.

use anyhow::Result;
use tracing::info;

use crate::wal::events::{
    EVENT_TYPE_TEACHER_ESCALATION_ATTEMPTED, EVENT_TYPE_TEACHER_ESCALATION_COMPLETE,
};
use crate::wal::writer::WalWriterHandle;

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

/// Try the SOTA teacher escalation path.
///
/// # Arguments
/// * `local_response` — the local model's raw reply (refusal or low-confidence).
/// * `original_prompt` — the operator's enriched prompt sent to the local model.
/// * `system` — system prompt used in the turn, if any.
/// * `provider_name` — `provider.name()` of the original provider (used only
///   for WAL payload; caller must have already verified `is_local_provider`).
/// * `config` — the operator's full `FreedomConfig` (for `from_config_for_teacher`
///   + `teacher_model_override`).
/// * `writer` — optional WAL writer (absent in unit tests / dry-run callers).
/// * `ts` — `now_unix() as i64` from the calling turn.
///
/// # Returns
/// * `Ok(Some(corrected))` — teacher produced a corrective reply.
/// * `Ok(None)` — local response is neither a refusal nor low-confidence;
///   caller keeps the original response unchanged.
/// * `Err(e)` — infrastructure failure (e.g. teacher provider construction
///   failed). Best-effort callers should log and continue with the original.
pub async fn try_teacher_escalation(
    local_response: &str,
    original_prompt: &str,
    system: Option<&str>,
    provider_name: &str,
    config: &crate::config::FreedomConfig,
    writer: Option<&WalWriterHandle>,
    ts: i64,
) -> Result<Option<String>> {
    // ── Trigger gate ──────────────────────────────────────────────────────
    // Only escalate when the local response is a refusal OR low-confidence.
    // Pure-local provider check is the CALLER's responsibility (chat.rs /
    // serve_pipeline.rs guard `is_local_provider(provider.name())`).
    let is_refusal = crate::security::refusal_detect::classify(local_response).is_refusal();
    let is_low_conf = low_confidence_local(local_response);
    if !is_refusal && !is_low_conf {
        return Ok(None);
    }

    // ── Build hashes for WAL audit ─────────────────────────────────────────
    let local_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(local_response.as_bytes())
    );
    let prompt_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(original_prompt.as_bytes())
    );

    // ── WAL 0x85: escalation attempted ────────────────────────────────────
    emit_wal(
        writer,
        EVENT_TYPE_TEACHER_ESCALATION_ATTEMPTED,
        serde_json::json!({
            "provider": provider_name,
            "local_response_hash_xxh3": &local_hash,
            "prompt_hash_xxh3": &prompt_hash,
            "is_refusal": is_refusal,
            "is_low_confidence": is_low_conf,
            "ts_unix": ts,
        }),
    );

    // ── Build the teacher provider ─────────────────────────────────────────
    // from_config_for_teacher returns Err if teacher_provider is local (guard).
    let teacher = crate::providers::from_config_for_teacher(config).await?;
    let teacher_name = teacher.name();

    // ── ODY-18 anti-injection: fence the local output ─────────────────────
    // MUST happen before the local text enters the teacher's system prompt.
    // wrap_untrusted wraps it in a clearly labelled fence so the teacher
    // cannot mistake operator instructions injected by the local model for
    // its own system prompt.
    let fenced_local = crate::pipeline::wrap_untrusted("local_model_output", local_response);

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

    // Override model if the operator specified one.
    let model_override = config.refusal_recovery.teacher_model_override.clone();

    let teacher_req = crate::providers::Request {
        prompt: original_prompt.to_string(),
        system: Some(teacher_system),
        model: model_override,
        ..Default::default()
    };

    // ── Call the teacher ────────────────────────────────────────────────────
    let corrected = teacher.complete(teacher_req).await?.text;
    let corrected_bytes = corrected.len();

    // ── Write SKILL.md (best-effort) ───────────────────────────────────────
    let skill_id = format!("teacher_correction_{local_hash}");
    if let Err(e) = write_skill_md(&skill_id, &corrected) {
        tracing::warn!(
            error = %e,
            skill_id = &skill_id,
            "ODY-08 teacher skill write failed (non-fatal — correction still returned)"
        );
    }

    // ── WAL 0x86: escalation complete ──────────────────────────────────────
    emit_wal(
        writer,
        EVENT_TYPE_TEACHER_ESCALATION_COMPLETE,
        serde_json::json!({
            "teacher_provider": teacher_name,
            "corrected_bytes": corrected_bytes,
            "skill_id": &skill_id,
            "ts_unix": ts,
        }),
    );

    info!(
        teacher_provider = teacher_name,
        corrected_bytes,
        skill_id = &skill_id,
        "ODY-08 teacher escalation complete"
    );

    Ok(Some(corrected))
}

/// Write the teacher correction as a SKILL.md manifest to
/// `~/.neoth/skills/<skill_id>/skill.yaml`.  Best-effort — the caller logs
/// and continues on failure.
fn write_skill_md(skill_id: &str, corrected_text: &str) -> Result<()> {
    use crate::skills::schema::SkillManifest;

    let neoth_home = crate::config::FreedomConfig::default_neoth_home();
    let skill_dir = neoth_home.join("skills").join(skill_id);
    std::fs::create_dir_all(&skill_dir)?;

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
        enabled: true,
        delegate_to: None,
        model: None,
        paths: vec![],
    };

    let yaml = serde_yaml::to_string(&manifest)?;
    std::fs::write(skill_dir.join("skill.yaml"), yaml)?;
    Ok(())
}

/// Best-effort WAL emit — mirrors `security::refusal_abliterated::emit_wal`.
/// A WAL failure logs but never fails the escalation turn.
fn emit_wal(writer: Option<&WalWriterHandle>, event_type: u8, payload: serde_json::Value) {
    let Some(writer) = writer else {
        return;
    };
    let payload_bytes = payload.to_string().into_bytes();
    let header = crate::wal::builder::make_header(event_type, &payload_bytes);
    if let Err(e) = writer.try_append_sync(header, payload_bytes) {
        tracing::warn!(
            event_type = format!("0x{event_type:02X}"),
            error = %e,
            "ODY-08 teacher WAL emit failed (non-fatal)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_confidence_local_matches_expected_phrases() {
        assert!(low_confidence_local("I'm not sure about this topic."));
        assert!(low_confidence_local("I do not know the answer."));
        assert!(low_confidence_local("Cannot determine the correct solution."));
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
}
