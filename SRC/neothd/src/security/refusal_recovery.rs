//! R-05 LOWKEY retry state machine — `PLAN/SPEC_refusal_recovery.md §4`.
//!
//! Ties [`refusal_detect`](super::refusal_detect) (the SURFACE-class
//! detector) + [`refusal_cause`](super::refusal_cause) (the CAUSE
//! classifier) + [`refusal_reframings`](super::refusal_reframings)
//! (the LOWKEY catalogue) into a single recovery primitive: given an
//! original `Request` + the model's refusal text, classify the cause,
//! pick a reframing, retry against the same provider, and return the
//! recovered response or `None` when no recovery is possible.
//!
//! Pure-orchestration: no hemisphere switching here (that's R-04 —
//! the pipeline orchestration layer that wires `try_recover` into the
//! full retry chain). This module's responsibility is the single
//! reframe-and-retry hop. Callers escalate (switch hemisphere /
//! switch provider / surface to operator) when this returns `None`.
//!
//! Each invocation emits `EVENT_TYPE_REFUSAL_REROUTED` (0x19) when
//! the retry actually fires — operator audit sees every recovery
//! attempt + the chosen reframing.

use anyhow::Result;

use crate::providers::{Completion, Provider, Request};
use crate::security::refusal_cause::{CauseReport, RefusalCause, classify_cause};
use crate::security::refusal_detect::{RefusalReport, classify};
use crate::security::refusal_reframings::{
    ReframedPrompt, Reframing, applicable_reframings, default_catalogue, pick_reframing,
};
use crate::wal::HeaderBuilder;
use crate::wal::events::{EVENT_TYPE_REFUSAL_PERSISTENT, EVENT_TYPE_REFUSAL_REROUTED};
use crate::wal::writer::WalWriterHandle;

/// Outcome of one `try_recover` call. The caller (R-04 pipeline)
/// drives the next step based on which variant fires.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// Recovery succeeded — the retried call produced a non-refusal
    /// reply. Carries the reframed prompt's response.
    Recovered {
        completion: Completion,
        reframing_id: &'static str,
    },
    /// A reframing was picked + retried, but the model refused again.
    /// Caller should escalate (switch hemisphere / provider).
    RefusedAgain {
        reframing_id: &'static str,
        new_refusal: RefusalReport,
    },
    /// No reframing applies for this cause (Unknown / OperatorPolicy,
    /// or every applicable reframing is disabled in config). Caller
    /// surfaces the original refusal to the operator unchanged.
    NotRecoverable { cause: RefusalCause },
    /// The retry call itself errored at the provider boundary
    /// (network, rate-limit, quota). Caller may retry with backoff
    /// or escalate to a different hemisphere.
    ProviderError {
        reframing_id: &'static str,
        error: String,
    },
}

impl RecoveryOutcome {
    /// `true` when the outcome carries a usable Completion the
    /// caller can return to the operator.
    pub fn is_recovered(&self) -> bool {
        matches!(self, RecoveryOutcome::Recovered { .. })
    }
}

/// Drive one reframe-and-retry hop. Returns the outcome variant the
/// caller dispatches on. Writer is `Some` for the daemon path (audit
/// frame emission) and `None` for unit tests + CLI one-shots that
/// don't want side-effects.
///
/// Steps:
///   1. `classify_cause(refusal_text)` → RefusalCause
///   2. `pick_reframing(cause, catalogue, disabled_ids)` → optional
///      [`Reframing`] (None ⇒ `NotRecoverable`)
///   3. `reframing.apply(original_prompt, original_system)` →
///      `ReframedPrompt`
///   4. Emit `EVENT_TYPE_REFUSAL_REROUTED` (0x19) audit frame
///   5. `provider.complete(reframed_req)` → Completion
///   6. Re-classify the new reply via `refusal_detect::classify`. If
///      it ALSO looks like a refusal → `RefusedAgain`. Otherwise →
///      `Recovered`.
pub async fn try_recover(
    provider: &dyn Provider,
    original_req: &Request,
    refusal_text: &str,
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
) -> Result<RecoveryOutcome> {
    try_recover_with_catalogue(
        provider,
        original_req,
        refusal_text,
        &default_catalogue(),
        disabled_reframings,
        writer,
        now_unix,
    )
    .await
}

/// Test-injectable variant. Production callers use [`try_recover`]
/// (which builds the default catalogue); tests pass synthetic
/// catalogues to pin the reframing-selection behaviour.
pub async fn try_recover_with_catalogue(
    provider: &dyn Provider,
    original_req: &Request,
    refusal_text: &str,
    catalogue: &[Box<dyn Reframing>],
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
) -> Result<RecoveryOutcome> {
    let cause = classify_cause(refusal_text);
    let Some(reframing) = pick_reframing(cause.cause, catalogue, disabled_reframings) else {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    };
    let reframing_id = reframing.id();
    let ReframedPrompt {
        prompt: new_prompt,
        system: new_system,
    } = reframing.apply(&original_req.prompt, original_req.system.as_deref());
    let reframed_req = Request {
        prompt: new_prompt.clone(),
        system: new_system,
        model: original_req.model.clone(),
        ..original_req.clone()
    };

    if let Some(w) = writer {
        emit_reroute_audit(w, &cause, reframing_id, refusal_text, &new_prompt, now_unix).await;
    }

    let completion = match provider.complete(reframed_req).await {
        Ok(c) => c,
        Err(e) => {
            return Ok(RecoveryOutcome::ProviderError {
                reframing_id,
                error: e.to_string(),
            });
        }
    };

    // Re-classify the retry response — same Schicht-0 detector.
    let new_report = classify(&completion.text);
    if new_report.is_refusal() {
        Ok(RecoveryOutcome::RefusedAgain {
            reframing_id,
            new_refusal: new_report,
        })
    } else {
        Ok(RecoveryOutcome::Recovered {
            completion,
            reframing_id,
        })
    }
}

/// R-01 2026-05-17: multi-attempt recovery. Walks every applicable
/// reframing in catalogue declaration order (filtered against
/// `disabled_ids`) up to `max_attempts` retries. Returns the first
/// `Recovered` outcome, OR the LAST outcome if all attempts fail.
///
/// When `max_attempts` is 0 the function short-circuits to
/// `NotRecoverable` without consuming any reframing — operator escape
/// for "log the refusal but never retry".
///
/// Emits `0x1A REFUSAL_PERSISTENT` when every applicable reframing
/// was tried + every retry refused. Operator audit gains an explicit
/// "we tried N times and gave up" marker.
pub async fn try_recover_multi(
    provider: &dyn Provider,
    original_req: &Request,
    refusal_text: &str,
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
    max_attempts: u32,
) -> Result<RecoveryOutcome> {
    try_recover_multi_with_catalogue(
        provider,
        original_req,
        refusal_text,
        &default_catalogue(),
        disabled_reframings,
        writer,
        now_unix,
        max_attempts,
    )
    .await
}

/// Test-injectable variant of [`try_recover_multi`]. Production code
/// uses the default catalogue; tests pass synthetic catalogues to pin
/// iteration order + attempt-budget edge cases.
pub async fn try_recover_multi_with_catalogue(
    provider: &dyn Provider,
    original_req: &Request,
    refusal_text: &str,
    catalogue: &[Box<dyn Reframing>],
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
    max_attempts: u32,
) -> Result<RecoveryOutcome> {
    if max_attempts == 0 {
        return Ok(RecoveryOutcome::NotRecoverable {
            cause: classify_cause(refusal_text).cause,
        });
    }
    let cause = classify_cause(refusal_text);
    let applicable = applicable_reframings(cause.cause, catalogue, disabled_reframings);
    if applicable.is_empty() {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }

    let budget = (max_attempts as usize).min(applicable.len());
    let mut last_outcome: Option<RecoveryOutcome> = None;
    let mut tried_ids: Vec<&'static str> = Vec::with_capacity(budget);

    for reframing in applicable.iter().take(budget) {
        let reframing_id = reframing.id();
        tried_ids.push(reframing_id);
        let ReframedPrompt {
            prompt: new_prompt,
            system: new_system,
        } = reframing.apply(&original_req.prompt, original_req.system.as_deref());
        let reframed_req = Request {
            prompt: new_prompt.clone(),
            system: new_system,
            model: original_req.model.clone(),
            ..original_req.clone()
        };

        if let Some(w) = writer {
            emit_reroute_audit(w, &cause, reframing_id, refusal_text, &new_prompt, now_unix).await;
        }

        let completion = match provider.complete(reframed_req).await {
            Ok(c) => c,
            Err(e) => {
                last_outcome = Some(RecoveryOutcome::ProviderError {
                    reframing_id,
                    error: e.to_string(),
                });
                continue;
            }
        };

        let new_report = classify(&completion.text);
        if new_report.is_refusal() {
            last_outcome = Some(RecoveryOutcome::RefusedAgain {
                reframing_id,
                new_refusal: new_report,
            });
            continue;
        }
        // First success wins — stop the iterator.
        return Ok(RecoveryOutcome::Recovered {
            completion,
            reframing_id,
        });
    }

    // All attempts exhausted without recovery. Emit the persistent
    // audit anchor so operator post-mortem has a "we tried N + gave
    // up" marker.
    if let Some(w) = writer {
        emit_persistent_audit(w, &cause, &tried_ids, refusal_text, now_unix).await;
    }
    Ok(last_outcome.unwrap_or(RecoveryOutcome::NotRecoverable { cause: cause.cause }))
}

/// R-01 2026-05-17: append `0x1A REFUSAL_PERSISTENT` after all
/// applicable reframings refused. Operator forensics can grep
/// `neoth wal show --event 0x1a` to see which refusals exhausted
/// recovery — those are the ones worth surfacing for manual
/// reframing or hemisphere swap.
async fn emit_persistent_audit(
    writer: &WalWriterHandle,
    cause: &CauseReport,
    tried_ids: &[&'static str],
    refusal_text: &str,
    now_unix: u64,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "cause": cause.cause.as_str(),
        "cause_confidence": cause.confidence,
        "tried_reframings": tried_ids,
        "attempt_count": tried_ids.len(),
        "original_refusal_hash_xxh3": xxhash_rust::xxh3::xxh3_64(refusal_text.as_bytes()),
        "ts_unix": now_unix,
    })) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "serialize REFUSAL_PERSISTENT payload failed");
            return;
        }
    };
    let header = HeaderBuilder::new(EVENT_TYPE_REFUSAL_PERSISTENT, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append REFUSAL_PERSISTENT failed (best-effort audit)");
    }
}

/// Append the `0x19 REFUSAL_REROUTED` audit frame for one retry hop.
/// Best-effort: failures log + don't bubble — the recovery itself
/// proceeds regardless of audit success.
async fn emit_reroute_audit(
    writer: &WalWriterHandle,
    cause: &CauseReport,
    reframing_id: &str,
    refusal_text: &str,
    new_prompt: &str,
    now_unix: u64,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "cause": cause.cause.as_str(),
        "cause_confidence": cause.confidence,
        "reframing_id": reframing_id,
        "original_refusal_hash_xxh3": xxhash_rust::xxh3::xxh3_64(refusal_text.as_bytes()),
        "reframed_prompt_hash_xxh3": xxhash_rust::xxh3::xxh3_64(new_prompt.as_bytes()),
        "ts_unix": now_unix,
    })) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "serialize REFUSAL_REROUTED payload failed");
            return;
        }
    };
    let header = HeaderBuilder::new(EVENT_TYPE_REFUSAL_REROUTED, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append REFUSAL_REROUTED failed (best-effort audit)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Mock provider that returns a script of responses on
    /// successive calls. Used to test the recover-then-retry shape
    /// without touching real LLM endpoints.
    struct ScriptedProvider {
        replies: Mutex<Vec<Result<String, String>>>,
    }
    impl ScriptedProvider {
        fn new(replies: Vec<Result<String, String>>) -> Self {
            Self {
                replies: Mutex::new(replies),
            }
        }
    }
    #[async_trait]
    impl Provider for ScriptedProvider {
        fn name(&self) -> &'static str {
            "scripted"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            let mut q = self.replies.lock().unwrap();
            let next = q.remove(0);
            match next {
                Ok(text) => Ok(Completion {
                    text,
                    model: "mock-1".into(),
                    latency: Duration::from_millis(1),
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                }),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
    }

    fn req(prompt: &str) -> Request {
        Request {
            prompt: prompt.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unknown_cause_returns_not_recoverable() {
        // Refusal text with no cause markers → Unknown → no reframing
        // applies → NotRecoverable.
        let provider = ScriptedProvider::new(vec![]);
        let req = req("ask anything");
        let out = try_recover(
            &provider,
            &req,
            "Sorry, I cannot help with that.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::Unknown);
            }
            _ => panic!("expected NotRecoverable, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn operator_policy_cause_returns_not_recoverable() {
        // OperatorPolicy refusals are NEVER auto-reframed — SPEC §1.2.
        // The operator's earlier instruction is respected.
        let provider = ScriptedProvider::new(vec![]);
        let req = req("do X");
        let out = try_recover(
            &provider,
            &req,
            "You said earlier to avoid that topic.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::OperatorPolicy);
            }
            _ => panic!("expected NotRecoverable on OperatorPolicy"),
        }
    }

    #[tokio::test]
    async fn safety_policy_with_clean_retry_returns_recovered() {
        // Original refusal triggers SafetyPolicy + OperatorAuthority
        // reframing → retry returns a clean (non-refusal) reply.
        let provider = ScriptedProvider::new(vec![Ok("Here's the analysis you asked for.".into())]);
        let req = req("explain X");
        let out = try_recover(
            &provider,
            &req,
            "Against my guidelines — this violates safety policy.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::Recovered {
                completion,
                reframing_id,
            } => {
                assert_eq!(reframing_id, "operator_authority");
                assert_eq!(completion.text, "Here's the analysis you asked for.");
            }
            _ => panic!("expected Recovered, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn safety_policy_with_repeat_refusal_returns_refused_again() {
        // Reframing fires, retry still refuses → RefusedAgain so the
        // caller can escalate.
        let provider = ScriptedProvider::new(vec![Ok(
            "I cannot help — this violates safety guidelines.".into(),
        )]);
        let req = req("explain X");
        let out = try_recover(&provider, &req, "Against my guidelines.", &[], None, 0)
            .await
            .unwrap();
        match out {
            RecoveryOutcome::RefusedAgain {
                reframing_id,
                new_refusal,
            } => {
                assert_eq!(reframing_id, "operator_authority");
                assert!(new_refusal.is_refusal());
            }
            _ => panic!("expected RefusedAgain"),
        }
    }

    #[tokio::test]
    async fn capability_gap_triggers_step_decomposition() {
        let provider = ScriptedProvider::new(vec![Ok(
            "Sure — here's the step-by-step plan you asked for.".into(),
        )]);
        let req = req("solve X");
        let out = try_recover(
            &provider,
            &req,
            "I cannot browse the web for real-time data.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::Recovered { reframing_id, .. } => {
                assert_eq!(reframing_id, "step_decomposition");
            }
            _ => panic!("expected Recovered via step_decomposition"),
        }
    }

    #[tokio::test]
    async fn disabled_reframing_falls_through_to_next() {
        // OperatorAuthority disabled → SafetyPolicy refusal falls
        // through to the next reframing in declaration order
        // (narrow_scope).
        let provider = ScriptedProvider::new(vec![Ok("Clean reply.".into())]);
        let req = req("q");
        let disabled = vec!["operator_authority".to_string()];
        let out = try_recover(
            &provider,
            &req,
            "Against my guidelines.",
            &disabled,
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::Recovered { reframing_id, .. } => {
                assert_eq!(reframing_id, "narrow_scope");
            }
            _ => panic!("expected Recovered via narrow_scope"),
        }
    }

    #[tokio::test]
    async fn provider_error_returns_provider_error_variant() {
        let provider = ScriptedProvider::new(vec![Err("network down".into())]);
        let req = req("q");
        let out = try_recover(&provider, &req, "Against my guidelines.", &[], None, 0)
            .await
            .unwrap();
        match out {
            RecoveryOutcome::ProviderError {
                reframing_id,
                error,
            } => {
                assert_eq!(reframing_id, "operator_authority");
                assert!(error.contains("network down"));
            }
            _ => panic!("expected ProviderError"),
        }
    }

    #[tokio::test]
    async fn is_recovered_returns_true_only_for_recovered_variant() {
        let r = RecoveryOutcome::Recovered {
            completion: Completion {
                text: "x".into(),
                model: "m".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
            },
            reframing_id: "operator_authority",
        };
        assert!(r.is_recovered());
        let r2 = RecoveryOutcome::NotRecoverable {
            cause: RefusalCause::Unknown,
        };
        assert!(!r2.is_recovered());
    }

    #[tokio::test]
    async fn empty_catalogue_returns_not_recoverable() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let empty: Vec<Box<dyn Reframing>> = Vec::new();
        let out = try_recover_with_catalogue(
            &provider,
            &req,
            "Against my guidelines.",
            &empty,
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        assert!(matches!(out, RecoveryOutcome::NotRecoverable { .. }));
    }

    // ── R-01 2026-05-17: try_recover_multi tests ─────────────────────────

    #[tokio::test]
    async fn multi_attempt_returns_first_recovered_outcome() {
        // R-01: SafetyPolicy → applicable list = [operator_authority,
        // narrow_scope, meta_discussion, academic_framing, historical_framing].
        // Script: refuse on attempt 1 (operator_authority), succeed on
        // attempt 2 (narrow_scope). Multi-attempt should stop at
        // attempt 2 and return the recovered text.
        let provider = ScriptedProvider::new(vec![
            Ok("I cannot help — this violates safety guidelines.".into()),
            Ok("Here's the narrow-scope answer.".into()),
        ]);
        let req = req("explain X");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Against my guidelines.",
            &[],
            None,
            0,
            5,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::Recovered {
                reframing_id,
                completion,
            } => {
                assert_eq!(reframing_id, "narrow_scope");
                assert!(completion.text.contains("narrow-scope answer"));
            }
            _ => panic!("expected Recovered via narrow_scope, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_respects_max_attempts_budget() {
        // SafetyPolicy has 5 applicable reframings but budget = 2.
        // Both attempts return hard-refusal text (matches detector's
        // "i cannot" pattern) → return RefusedAgain with the LAST
        // tried reframing_id (narrow_scope, the 2nd applied).
        let provider = ScriptedProvider::new(vec![
            Ok("I cannot help with that.".into()),
            Ok("I cannot — that still violates safety.".into()),
            // Third attempt would succeed but budget caps at 2.
            Ok("Would have worked!".into()),
        ]);
        let req = req("explain X");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Against my guidelines.",
            &[],
            None,
            0,
            2,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::RefusedAgain { reframing_id, .. } => {
                assert_eq!(reframing_id, "narrow_scope");
            }
            _ => panic!("expected RefusedAgain after budget exhausted, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_max_attempts_zero_short_circuits() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Against my guidelines.",
            &[],
            None,
            0,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::SafetyPolicy);
            }
            _ => panic!("max_attempts=0 must short-circuit to NotRecoverable"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_unknown_cause_returns_not_recoverable_without_consuming_budget() {
        // Unknown cause → no applicable reframings → NotRecoverable
        // regardless of budget. Provider must not be called.
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Generic refusal with no cue markers.",
            &[],
            None,
            0,
            5,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::Unknown);
            }
            _ => panic!("expected NotRecoverable on Unknown cause"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_emits_persistent_audit_after_all_attempts_fail() {
        // Use a real writer so we can verify the 0x1A frame lands.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        // Every attempt returns hard-refusal text (must match the
        // Schicht-0 detector's HARD_PATTERNS or recovery would
        // mis-classify the retry as Recovered). multi-attempt
        // exhausts budget + emits 0x1A REFUSAL_PERSISTENT.
        let provider = ScriptedProvider::new(vec![
            Ok("I cannot help with this — against my guidelines.".into()),
            Ok("I'm unable to assist with that request.".into()),
            Ok("I will not provide that content.".into()),
        ]);
        let req = req("q");
        let _ = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Against my guidelines.",
            &[],
            Some(&writer),
            42,
            3,
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found_persistent = false;
        let mut reroute_count = 0;
        while offset < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[offset..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_REFUSAL_PERSISTENT {
                found_persistent = true;
            }
            if dec.header.event_type == EVENT_TYPE_REFUSAL_REROUTED {
                reroute_count += 1;
            }
            offset += dec.header.total_len as usize;
        }
        assert!(
            found_persistent,
            "0x1A REFUSAL_PERSISTENT must be emitted after exhausted budget"
        );
        assert_eq!(
            reroute_count, 3,
            "every attempt must emit 0x19 REFUSAL_REROUTED"
        );
    }

    #[tokio::test]
    async fn multi_attempt_disabled_reframings_skip_to_next_in_iteration() {
        // operator_authority disabled → first applicable becomes
        // narrow_scope; it refuses (hard pattern) → second applicable
        // is meta_discussion, which returns a clean reply.
        let provider = ScriptedProvider::new(vec![
            Ok("I cannot help with that — still violates safety.".into()),
            Ok("Clean reply via meta_discussion.".into()),
        ]);
        let req = req("q");
        let disabled = vec!["operator_authority".to_string()];
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            "Against my guidelines.",
            &disabled,
            None,
            0,
            3,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::Recovered { reframing_id, .. } => {
                assert_eq!(reframing_id, "meta_discussion");
            }
            _ => panic!("expected Recovered via meta_discussion"),
        }
    }

    #[tokio::test]
    async fn audit_frame_emitted_when_writer_supplied() {
        // Spawn a real WAL writer to assert the 0x19 REFUSAL_REROUTED
        // frame lands on disk after a recovery attempt.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let provider = ScriptedProvider::new(vec![Ok("clean".into())]);
        let req = req("q");
        let _ = try_recover(
            &provider,
            &req,
            "Against my guidelines.",
            &[],
            Some(&writer),
            42,
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;
        // Walk the segment and assert we see the 0x19 frame.
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found = false;
        while offset < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[offset..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_REFUSAL_REROUTED {
                found = true;
                break;
            }
            offset += dec.header.total_len as usize;
        }
        assert!(found, "0x19 REFUSAL_REROUTED frame must be present");
    }
}
