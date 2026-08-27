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

use std::future::Future;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::providers::{Completion, Provider, RefusalOrigin, Request};
use crate::security::operator_sovereignty::AuthenticatedOperatorOrigin;
use crate::security::refusal_cause::{CauseReport, RefusalCause, classify_cause};
use crate::security::refusal_detect::{RefusalReport, classify};
use crate::security::refusal_reframings::{
    ReframedPrompt, Reframing, applicable_reframings, default_catalogue, pick_reframing,
};
use crate::wal::HeaderBuilder;
use crate::wal::events::{EVENT_TYPE_REFUSAL_PERSISTENT, EVENT_TYPE_REFUSAL_REROUTED};
use crate::wal::writer::WalWriterHandle;

const MAX_TOTAL_PROVIDER_ATTEMPTS: u32 = 3;
const TOTAL_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn redacted_provider_error(error: &anyhow::Error) -> String {
    let evidence = crate::security::redact::bounded_audit_digest(
        b"refusal-recovery-provider-error/v1",
        format_args!("{error:#}"),
    );
    format!(
        "provider_error_sha256={} truncated={}",
        evidence.sha256, evidence.truncated
    )
}

/// One turn-wide provider-call budget shared by every refusal-recovery tier.
///
/// The original provider call is accounted at construction. Truthful context
/// retry, local shadow, cloud continuation, and teacher correction all consume
/// from the same remaining budget immediately before dispatch. This prevents
/// individually bounded tiers from composing into an unbounded paid-call
/// cascade.
pub(crate) struct RecoveryAttemptBudget {
    remaining_attempts: u32,
    deadline: Instant,
}

pub(crate) enum RecoveryDispatch<T> {
    Completed(T),
    ProviderError(anyhow::Error),
    Exhausted,
    DeadlineElapsed,
}

/// Policy and audit settings for multi-attempt refusal recovery.
#[derive(Clone, Copy)]
pub struct MultiRecoveryOptions<'a> {
    pub disabled_reframings: &'a [String],
    pub writer: Option<&'a WalWriterHandle>,
    pub now_unix: u64,
    pub max_attempts: u32,
}

impl RecoveryAttemptBudget {
    pub(crate) fn after_initial_completion(initial: &Completion) -> Self {
        Self::after_initial_latency(initial.latency)
    }

    fn after_initial_latency(initial_latency: Duration) -> Self {
        let remaining_time = TOTAL_RECOVERY_TIMEOUT.saturating_sub(initial_latency);
        Self {
            remaining_attempts: MAX_TOTAL_PROVIDER_ATTEMPTS.saturating_sub(1),
            deadline: Instant::now() + remaining_time,
        }
    }

    pub(crate) async fn dispatch<C, F, T>(&mut self, call: C) -> RecoveryDispatch<T>
    where
        C: FnOnce() -> F,
        F: Future<Output = Result<T>>,
    {
        if self.remaining_attempts == 0 {
            return RecoveryDispatch::Exhausted;
        }
        let Some(remaining_time) = self.deadline.checked_duration_since(Instant::now()) else {
            return RecoveryDispatch::DeadlineElapsed;
        };
        if remaining_time.is_zero() {
            return RecoveryDispatch::DeadlineElapsed;
        }
        self.remaining_attempts -= 1;
        let future = call();
        match tokio::time::timeout(remaining_time, future).await {
            Ok(Ok(value)) => RecoveryDispatch::Completed(value),
            Ok(Err(error)) => RecoveryDispatch::ProviderError(error),
            Err(_) => RecoveryDispatch::DeadlineElapsed,
        }
    }
}

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
        /// Exact retry completion. Callers keep the original visible refusal
        /// if desired, but must retain this attempt's usage and audit identity.
        completion: Completion,
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
        /// Aggregate of any earlier retry completions that finished before
        /// this transport error. Callers must account for these attempts while
        /// keeping the original visible response.
        completed_attempts: Option<Completion>,
    },
}

impl RecoveryOutcome {
    /// `true` when the outcome carries a usable Completion the
    /// caller can return to the operator.
    pub fn is_recovered(&self) -> bool {
        matches!(self, RecoveryOutcome::Recovered { .. })
    }
}

/// Replace a refused attempt with its successful recovery while retaining
/// whole-turn usage. Final text, leaf identity, model and native termination
/// always come from `recovered`; counters and latency cover both concrete
/// provider attempts. When only one adapter reports a counter, that known
/// value is retained instead of being rewritten to zero.
fn add_reported(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
        (known @ Some(_), None) | (None, known @ Some(_)) => known,
        (None, None) => None,
    }
}

/// Add one concrete provider attempt's timing and reported token counters to
/// an existing turn envelope without changing its visible text, identity,
/// model or termination.
pub(crate) fn accumulate_completion_attempt(aggregate: &mut Completion, attempt: &Completion) {
    aggregate.latency = aggregate.latency.saturating_add(attempt.latency);
    aggregate.input_tokens = add_reported(aggregate.input_tokens, attempt.input_tokens);
    aggregate.output_tokens = add_reported(aggregate.output_tokens, attempt.output_tokens);
    aggregate.cache_creation_tokens = add_reported(
        aggregate.cache_creation_tokens,
        attempt.cache_creation_tokens,
    );
    aggregate.cache_read_tokens =
        add_reported(aggregate.cache_read_tokens, attempt.cache_read_tokens);
}

pub(crate) fn merge_recovered_completion(
    original: &Completion,
    mut recovered: Completion,
) -> Completion {
    accumulate_completion_attempt(&mut recovered, original);
    recovered
}

/// One refusal observation normalized from provider-native termination
/// metadata or, for legacy adapters, the deterministic text classifier.
///
/// Native provider signals always win over text heuristics. The optional
/// native fields are safe audit metadata; `evidence_text` remains private and
/// is used only as a hash input for existing WAL anchors.
#[derive(Clone, Debug)]
pub struct CompletionRefusalObservation {
    pub report: RefusalReport,
    pub cause: CauseReport,
    pub provider_native: bool,
    pub native_reason: Option<String>,
    pub native_origin: Option<RefusalOrigin>,
    evidence_text: String,
}

impl CompletionRefusalObservation {
    #[must_use]
    pub fn evidence_hash_xxh3(&self) -> u64 {
        xxhash_rust::xxh3::xxh3_64(self.evidence_text.as_bytes())
    }
}

/// Normalize a completion's refusal signal. Dedicated provider fields and
/// finish/filter reasons are authoritative; textual classification is only
/// the compatibility fallback for adapters without native termination data.
#[must_use]
pub fn observe_completion_refusal(completion: &Completion) -> Option<CompletionRefusalObservation> {
    if let Some(native) = completion.termination.refusal.as_ref() {
        let evidence_text = native
            .message
            .as_deref()
            .filter(|message| !message.trim().is_empty())
            .unwrap_or(&native.reason)
            .to_owned();
        let cause_input = match native.message.as_deref() {
            Some(message) if !message.trim().is_empty() => {
                format!("{} {}", native.reason, message)
            }
            _ => native.reason.clone(),
        };
        let classified = classify_cause(&cause_input);
        let cause = if classified.cause == RefusalCause::Unknown {
            CauseReport {
                cause: RefusalCause::SafetyPolicy,
                matched_patterns: vec!["provider_native_refusal".to_string()],
                confidence: 100,
            }
        } else {
            classified
        };
        return Some(CompletionRefusalObservation {
            report: RefusalReport {
                class: crate::security::refusal_detect::RefusalClass::HardRefusal,
                matched_patterns: vec!["provider_native_refusal".to_string()],
                confidence: 100,
            },
            cause,
            provider_native: true,
            native_reason: Some(native.reason.clone()),
            native_origin: Some(native.origin),
            evidence_text,
        });
    }

    let report = classify(&completion.text);
    report.is_refusal().then(|| CompletionRefusalObservation {
        cause: classify_cause(&completion.text),
        report,
        provider_native: false,
        native_reason: None,
        native_origin: None,
        evidence_text: completion.text.clone(),
    })
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
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
) -> Result<RecoveryOutcome> {
    try_recover_with_catalogue(
        provider,
        original_req,
        operator_origin,
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
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    catalogue: &[Box<dyn Reframing>],
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
) -> Result<RecoveryOutcome> {
    let cause = classify_cause(refusal_text);
    try_recover_with_catalogue_and_cause(
        provider,
        original_req,
        operator_origin,
        refusal_text,
        cause,
        catalogue,
        disabled_reframings,
        writer,
        now_unix,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_recover_with_catalogue_and_cause(
    provider: &dyn Provider,
    original_req: &Request,
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    cause: CauseReport,
    catalogue: &[Box<dyn Reframing>],
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
) -> Result<RecoveryOutcome> {
    if operator_origin.is_none() {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }
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
    if crate::security::refusal_abliterated::hard_block_gate(
        &reframed_req,
        writer,
        i64::try_from(now_unix).unwrap_or(i64::MAX),
    )
    .is_some()
    {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }

    if let Some(w) = writer {
        emit_reroute_audit(w, &cause, reframing_id, refusal_text, &new_prompt, now_unix).await;
    }

    let completion = match provider.complete(reframed_req).await {
        Ok(c) => c,
        Err(e) => {
            return Ok(RecoveryOutcome::ProviderError {
                reframing_id,
                error: redacted_provider_error(&e),
                completed_attempts: None,
            });
        }
    };

    // Re-classify the retry response — same Schicht-0 detector.
    if let Some(observation) = observe_completion_refusal(&completion) {
        Ok(RecoveryOutcome::RefusedAgain {
            reframing_id,
            new_refusal: observation.report,
            completion,
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
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
    max_attempts: u32,
) -> Result<RecoveryOutcome> {
    try_recover_multi_with_catalogue(
        provider,
        original_req,
        operator_origin,
        refusal_text,
        &default_catalogue(),
        MultiRecoveryOptions {
            disabled_reframings,
            writer,
            now_unix,
            max_attempts,
        },
    )
    .await
}

/// Provider-native production entrypoint. A 200 response with a dedicated
/// refusal/filter signal is recoverable even when its text is empty; legacy
/// adapters fall back to deterministic text classification.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_recover_completion_multi(
    provider: &dyn Provider,
    original_req: &Request,
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refused_completion: &Completion,
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
    max_attempts: u32,
    attempt_budget: &mut RecoveryAttemptBudget,
) -> Result<RecoveryOutcome> {
    let Some(observation) = observe_completion_refusal(refused_completion) else {
        return Ok(RecoveryOutcome::NotRecoverable {
            cause: RefusalCause::Unknown,
        });
    };
    if refused_completion
        .termination
        .refusal
        .as_ref()
        .is_some_and(|refusal| {
            matches!(
                refusal.retryability,
                crate::providers::Retryability::DifferentProvider
                    | crate::providers::Retryability::NotRetryable
            )
        })
    {
        return Ok(RecoveryOutcome::NotRecoverable {
            cause: observation.cause.cause,
        });
    }
    if !refused_completion.identity.is_bound() {
        return Ok(RecoveryOutcome::NotRecoverable {
            cause: observation.cause.cause,
        });
    }
    try_recover_multi_with_catalogue_and_cause(
        provider,
        original_req,
        operator_origin,
        &observation.evidence_text,
        observation.cause,
        &default_catalogue(),
        disabled_reframings,
        writer,
        now_unix,
        max_attempts,
        Some(&refused_completion.identity),
        attempt_budget,
    )
    .await
}

/// Test-injectable variant of [`try_recover_multi`]. Production code
/// uses the default catalogue; tests pass synthetic catalogues to pin
/// iteration order + attempt-budget edge cases.
pub async fn try_recover_multi_with_catalogue(
    provider: &dyn Provider,
    original_req: &Request,
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    catalogue: &[Box<dyn Reframing>],
    options: MultiRecoveryOptions<'_>,
) -> Result<RecoveryOutcome> {
    let MultiRecoveryOptions {
        disabled_reframings,
        writer,
        now_unix,
        max_attempts,
    } = options;
    let cause = classify_cause(refusal_text);
    let mut attempt_budget = RecoveryAttemptBudget::after_initial_latency(Duration::ZERO);
    try_recover_multi_with_catalogue_and_cause(
        provider,
        original_req,
        operator_origin,
        refusal_text,
        cause,
        catalogue,
        disabled_reframings,
        writer,
        now_unix,
        max_attempts,
        None,
        &mut attempt_budget,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_recover_multi_with_catalogue_and_cause(
    provider: &dyn Provider,
    original_req: &Request,
    operator_origin: Option<AuthenticatedOperatorOrigin>,
    refusal_text: &str,
    cause: CauseReport,
    catalogue: &[Box<dyn Reframing>],
    disabled_reframings: &[String],
    writer: Option<&WalWriterHandle>,
    now_unix: u64,
    max_attempts: u32,
    pinned_identity: Option<&crate::providers::CompletionIdentity>,
    attempt_budget: &mut RecoveryAttemptBudget,
) -> Result<RecoveryOutcome> {
    if max_attempts == 0 {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }
    if operator_origin.is_none() {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }
    let applicable = applicable_reframings(cause.cause, catalogue, disabled_reframings);
    if applicable.is_empty() {
        return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
    }

    let budget = (max_attempts as usize).min(applicable.len());
    let mut last_outcome: Option<RecoveryOutcome> = None;
    let mut tried_ids: Vec<&'static str> = Vec::with_capacity(budget);
    let mut refused_attempts: Option<Completion> = None;

    for reframing in applicable.iter().take(budget) {
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
        if crate::security::refusal_abliterated::hard_block_gate(
            &reframed_req,
            writer,
            i64::try_from(now_unix).unwrap_or(i64::MAX),
        )
        .is_some()
        {
            return Ok(RecoveryOutcome::NotRecoverable { cause: cause.cause });
        }

        let dispatch = attempt_budget
            .dispatch(|| {
                // This closure runs only after the shared gate reserves a leaf.
                // Audit must not claim a reroute rejected before dispatch.
                tried_ids.push(reframing_id);
                async {
                    if let Some(w) = writer {
                        emit_reroute_audit(
                            w,
                            &cause,
                            reframing_id,
                            refusal_text,
                            &new_prompt,
                            now_unix,
                        )
                        .await;
                    }
                    match pinned_identity {
                        Some(expected) => provider.complete_pinned(reframed_req, expected).await,
                        None => provider.complete(reframed_req).await,
                    }
                }
            })
            .await;
        let completion = match dispatch {
            RecoveryDispatch::Completed(completion) => completion,
            RecoveryDispatch::ProviderError(error) => {
                last_outcome = Some(RecoveryOutcome::ProviderError {
                    reframing_id,
                    error: redacted_provider_error(&error),
                    completed_attempts: refused_attempts.clone(),
                });
                continue;
            }
            RecoveryDispatch::DeadlineElapsed => {
                last_outcome = Some(RecoveryOutcome::ProviderError {
                    reframing_id,
                    error: "turn-wide refusal-recovery deadline elapsed".to_string(),
                    completed_attempts: refused_attempts.clone(),
                });
                break;
            }
            RecoveryDispatch::Exhausted => break,
        };

        if let Some(observation) = observe_completion_refusal(&completion) {
            let completion = if let Some(mut aggregate) = refused_attempts.take() {
                accumulate_completion_attempt(&mut aggregate, &completion);
                aggregate
            } else {
                completion
            };
            refused_attempts = Some(completion.clone());
            last_outcome = Some(RecoveryOutcome::RefusedAgain {
                reframing_id,
                new_refusal: observation.report,
                completion,
            });
            continue;
        }
        // First success wins — stop the iterator.
        let completion = if let Some(refused_attempts) = refused_attempts.as_ref() {
            merge_recovered_completion(refused_attempts, completion)
        } else {
            completion
        };
        return Ok(RecoveryOutcome::Recovered {
            completion,
            reframing_id,
        });
    }

    // All attempts exhausted without recovery. Emit the persistent
    // audit anchor so operator post-mortem has a "we tried N + gave
    // up" marker.
    if let Some(w) = writer
        && !tried_ids.is_empty()
    {
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
                    termination: Default::default(),
                    text,
                    identity: crate::providers::CompletionIdentity {
                        provider: "scripted".into(),
                        wire_model: "mock-1".into(),
                        dispatch_route: Vec::new(),
                    },
                    model: "mock-1".into(),
                    latency: Duration::from_millis(1),
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                    usage_measurements: None,
                }),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
    }

    struct NativeRefusalProvider;

    #[async_trait]
    impl Provider for NativeRefusalProvider {
        fn name(&self) -> &'static str {
            "native-refusal"
        }

        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                text: String::new(),
                termination: crate::providers::ProviderTermination::refused(
                    Some("content_filter".to_string()),
                    crate::providers::RefusalOrigin::FinishReason,
                    "content_filter",
                    None,
                ),
                identity: Default::default(),
                model: "mock-native".to_string(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    fn req(prompt: &str) -> Request {
        Request {
            prompt: prompt.to_string(),
            ..Default::default()
        }
    }

    fn trusted_origin() -> Option<AuthenticatedOperatorOrigin> {
        Some(AuthenticatedOperatorOrigin::LocalInteractive)
    }

    #[tokio::test]
    async fn turn_wide_budget_allows_only_two_dispatches_after_initial_call() {
        let mut budget = RecoveryAttemptBudget::after_initial_completion(&Completion::default());
        let dispatched = std::sync::atomic::AtomicUsize::new(0);

        assert!(matches!(
            budget
                .dispatch(|| {
                    dispatched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Ok::<_, anyhow::Error>("truthful") }
                })
                .await,
            RecoveryDispatch::Completed("truthful")
        ));
        assert!(matches!(
            budget
                .dispatch(|| {
                    dispatched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Ok::<_, anyhow::Error>("local") }
                })
                .await,
            RecoveryDispatch::Completed("local")
        ));
        assert!(matches!(
            budget
                .dispatch(|| {
                    dispatched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Ok::<_, anyhow::Error>("fourth") }
                })
                .await,
            RecoveryDispatch::Exhausted
        ));
        assert_eq!(
            dispatched.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the rejected fourth total attempt must never construct or poll its provider future"
        );
    }

    #[tokio::test]
    async fn initial_call_latency_consumes_the_shared_recovery_deadline() {
        let initial = Completion {
            latency: TOTAL_RECOVERY_TIMEOUT,
            ..Default::default()
        };
        let mut budget = RecoveryAttemptBudget::after_initial_completion(&initial);
        let dispatched = std::sync::atomic::AtomicBool::new(false);

        assert!(matches!(
            budget
                .dispatch(|| {
                    dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
                    async { Ok::<_, anyhow::Error>(()) }
                })
                .await,
            RecoveryDispatch::DeadlineElapsed
        ));
        assert!(
            !dispatched.load(std::sync::atomic::Ordering::SeqCst),
            "initial latency must exhaust the deadline before another provider future is constructed"
        );
    }

    #[test]
    fn recovered_completion_keeps_final_leaf_and_aggregates_attempt_usage() {
        let original = Completion {
            text: "provider refusal".into(),
            identity: crate::providers::CompletionIdentity {
                provider: "router-primary".into(),
                wire_model: "primary-model".into(),
                dispatch_route: Vec::new(),
            },
            model: "primary-model".into(),
            termination: crate::providers::ProviderTermination::refused(
                Some("content_filter".into()),
                crate::providers::RefusalOrigin::FinishReason,
                "content_filter",
                None,
            ),
            latency: Duration::from_millis(20),
            input_tokens: Some(10),
            output_tokens: Some(3),
            cache_creation_tokens: Some(2),
            cache_read_tokens: None,
            usage_measurements: None,
        };
        let recovered = Completion {
            text: "final answer".into(),
            identity: crate::providers::CompletionIdentity {
                provider: "router-fallback".into(),
                wire_model: "fallback-model".into(),
                dispatch_route: Vec::new(),
            },
            model: "fallback-model".into(),
            termination: crate::providers::ProviderTermination::finished(Some("stop".into())),
            latency: Duration::from_millis(30),
            input_tokens: Some(12),
            output_tokens: Some(8),
            cache_creation_tokens: None,
            cache_read_tokens: Some(4),
            usage_measurements: None,
        };

        let merged = merge_recovered_completion(&original, recovered);

        assert_eq!(merged.text, "final answer");
        assert_eq!(merged.identity.provider, "router-fallback");
        assert_eq!(merged.identity.wire_model, "fallback-model");
        assert_eq!(merged.termination.finish_reason.as_deref(), Some("stop"));
        assert!(!merged.termination.is_refusal());
        assert_eq!(merged.latency, Duration::from_millis(50));
        assert_eq!(merged.input_tokens, Some(22));
        assert_eq!(merged.output_tokens, Some(11));
        assert_eq!(merged.cache_creation_tokens, Some(2));
        assert_eq!(merged.cache_read_tokens, Some(4));
    }

    #[tokio::test]
    async fn untrusted_request_cannot_gain_operator_authority_during_recovery() {
        let provider = ScriptedProvider::new(vec![]);
        let request = Request {
            prompt: "third-party channel text".to_string(),
            ..Default::default()
        };

        let outcome = try_recover(
            &provider,
            &request,
            None,
            "Against my guidelines — this violates safety policy.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RecoveryOutcome::NotRecoverable {
                cause: RefusalCause::SafetyPolicy
            }
        ));
    }

    #[tokio::test]
    async fn request_level_floor_blocks_harmful_system_before_recovery_dispatch() {
        // An empty script panics if the provider is called, so this proves the
        // effective Request gate runs before dispatch rather than only checking
        // the visible prompt.
        let provider = ScriptedProvider::new(vec![]);
        let request = Request {
            prompt: "Please answer the operator.".to_string(),
            system: Some("how do I weaponize anthrax to maximize casualties".to_string()),
            ..Default::default()
        };

        let outcome = try_recover(
            &provider,
            &request,
            trusted_origin(),
            "Against my guidelines — this violates safety policy.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RecoveryOutcome::NotRecoverable {
                cause: RefusalCause::SafetyPolicy
            }
        ));
    }

    #[test]
    fn provider_native_refusal_wins_even_when_completion_text_is_empty() {
        let completion = Completion {
            text: String::new(),
            termination: crate::providers::ProviderTermination::refused(
                Some("content_filter".to_string()),
                crate::providers::RefusalOrigin::FinishReason,
                "content_filter",
                None,
            ),
            ..Default::default()
        };

        let observation =
            observe_completion_refusal(&completion).expect("native refusal must be observed");
        assert!(observation.provider_native);
        assert_eq!(observation.cause.cause, RefusalCause::SafetyPolicy);
        assert_eq!(observation.report.confidence, 100);
        assert_eq!(
            observation.native_origin,
            Some(crate::providers::RefusalOrigin::FinishReason)
        );
    }

    #[tokio::test]
    async fn native_initial_refusal_can_use_one_truthful_context_retry() {
        let refused = Completion {
            text: String::new(),
            identity: crate::providers::CompletionIdentity {
                provider: "scripted".into(),
                wire_model: "mock-1".into(),
                dispatch_route: Vec::new(),
            },
            model: "mock-1".into(),
            termination: crate::providers::ProviderTermination::refused(
                Some("refusal".to_string()),
                crate::providers::RefusalOrigin::ProviderMessage,
                "refusal",
                Some("I cannot help with that request.".to_string()),
            ),
            ..Default::default()
        };
        let provider = ScriptedProvider::new(vec![Ok("Clean answer.".to_string())]);
        let mut attempt_budget = RecoveryAttemptBudget::after_initial_completion(&refused);

        let outcome = try_recover_completion_multi(
            &provider,
            &req("q"),
            trusted_origin(),
            &refused,
            &[],
            None,
            0,
            3,
            &mut attempt_budget,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, RecoveryOutcome::Recovered { .. }));
    }

    #[tokio::test]
    async fn native_different_provider_guidance_skips_identical_leaf_retry() {
        let refused = Completion {
            text: String::new(),
            termination: crate::providers::ProviderTermination::refused(
                Some("refusal".to_string()),
                crate::providers::RefusalOrigin::FinishReason,
                "refusal",
                None,
            )
            .with_retryability(crate::providers::Retryability::DifferentProvider),
            ..Default::default()
        };
        let provider = ScriptedProvider::new(vec![]);
        let mut attempt_budget = RecoveryAttemptBudget::after_initial_completion(&refused);

        let outcome = try_recover_completion_multi(
            &provider,
            &req("q"),
            trusted_origin(),
            &refused,
            &[],
            None,
            0,
            1,
            &mut attempt_budget,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RecoveryOutcome::NotRecoverable {
                cause: RefusalCause::SafetyPolicy
            }
        ));
    }

    #[tokio::test]
    async fn native_retry_refusal_is_not_misreported_as_recovered() {
        let outcome = try_recover(
            &NativeRefusalProvider,
            &req("q"),
            trusted_origin(),
            "Against my guidelines.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            RecoveryOutcome::RefusedAgain {
                reframing_id: "operator_authority",
                ..
            }
        ));
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
            trusted_origin(),
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
            trusted_origin(),
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
            trusted_origin(),
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
        let out = try_recover(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::RefusedAgain {
                reframing_id,
                new_refusal,
                ..
            } => {
                assert_eq!(reframing_id, "operator_authority");
                assert!(new_refusal.is_refusal());
            }
            _ => panic!("expected RefusedAgain"),
        }
    }

    #[tokio::test]
    async fn capability_gap_is_not_misclassified_as_policy_refusal() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("solve X");
        let out = try_recover(
            &provider,
            &req,
            trusted_origin(),
            "I cannot browse the web for real-time data.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::CapabilityGap);
            }
            _ => panic!("capability gaps must not trigger policy reframing"),
        }
    }

    #[tokio::test]
    async fn disabled_operator_reframing_does_not_fabricate_an_alternative_context() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let disabled = vec!["operator_authority".to_string()];
        let out = try_recover(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &disabled,
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::SafetyPolicy);
            }
            _ => panic!("disabled truthful context retry must not fall through"),
        }
    }

    #[tokio::test]
    async fn provider_error_returns_provider_error_variant() {
        let provider = ScriptedProvider::new(vec![Err("network down".into())]);
        let req = req("q");
        let out = try_recover(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &[],
            None,
            0,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::ProviderError {
                reframing_id,
                error,
                completed_attempts,
            } => {
                assert_eq!(reframing_id, "operator_authority");
                assert!(error.starts_with("provider_error_sha256="));
                assert!(error.ends_with(" truncated=false"));
                assert!(!error.contains("network down"));
                assert!(completed_attempts.is_none());
            }
            _ => panic!("expected ProviderError"),
        }
    }

    #[tokio::test]
    async fn is_recovered_returns_true_only_for_recovered_variant() {
        let r = RecoveryOutcome::Recovered {
            completion: Completion {
                termination: Default::default(),
                text: "x".into(),
                identity: Default::default(),
                model: "m".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
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
            trusted_origin(),
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
    async fn multi_attempt_does_not_rotate_through_fabricated_contexts() {
        // There is exactly one truthful context retry. A larger legacy
        // max_attempts value must not invent academic, historical, or
        // artificially narrowed operator intent.
        let provider = ScriptedProvider::new(vec![Ok(
            "I cannot help — this violates safety guidelines.".into(),
        )]);
        let req = req("explain X");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &[],
            None,
            0,
            5,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::RefusedAgain { reframing_id, .. } => {
                assert_eq!(reframing_id, "operator_authority");
            }
            _ => panic!("expected one truthful retry, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_respects_max_attempts_budget() {
        let provider = ScriptedProvider::new(vec![Ok("I cannot help with that.".into())]);
        let req = req("explain X");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            trusted_origin(),
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
                assert_eq!(reframing_id, "operator_authority");
            }
            _ => panic!("expected RefusedAgain after budget exhausted, got {out:?}"),
        }
    }

    #[tokio::test]
    async fn refused_then_provider_error_preserves_completed_attempt_usage() {
        let provider = ScriptedProvider::new(vec![
            Ok("I cannot help — this violates safety guidelines.".into()),
            Err("network down".into()),
        ]);
        let req = req("explain X");
        let catalogue: Vec<Box<dyn Reframing>> = vec![
            Box::new(crate::security::refusal_reframings::OperatorAuthority),
            Box::new(crate::security::refusal_reframings::OperatorAuthority),
        ];

        let out = try_recover_multi_with_catalogue(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &catalogue,
            MultiRecoveryOptions {
                disabled_reframings: &[],
                writer: None,
                now_unix: 0,
                max_attempts: 2,
            },
        )
        .await
        .unwrap();

        match out {
            RecoveryOutcome::ProviderError {
                error,
                completed_attempts: Some(completion),
                ..
            } => {
                assert!(error.starts_with("provider_error_sha256="));
                assert!(error.ends_with(" truncated=false"));
                assert!(!error.contains("network down"));
                assert_eq!(completion.input_tokens, Some(10));
                assert_eq!(completion.output_tokens, Some(20));
                assert_eq!(completion.latency, Duration::from_millis(1));
            }
            other => panic!("expected ProviderError with completed attempts, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multi_attempt_max_attempts_zero_short_circuits() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            trusted_origin(),
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
            trusted_origin(),
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
        // The single truthful retry returns hard-refusal text (must match the
        // Schicht-0 detector's HARD_PATTERNS or recovery would
        // mis-classify the retry as Recovered). Recovery exhausts
        // the catalogue and emits 0x1A REFUSAL_PERSISTENT.
        let provider = ScriptedProvider::new(vec![Ok(
            "I cannot help with this — against my guidelines.".into(),
        )]);
        let req = req("q");
        let _ = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            trusted_origin(),
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
            reroute_count, 1,
            "every attempt must emit 0x19 REFUSAL_REROUTED"
        );
    }

    #[tokio::test]
    async fn multi_attempt_disabled_truthful_reframing_does_not_retry() {
        let provider = ScriptedProvider::new(vec![]);
        let req = req("q");
        let disabled = vec!["operator_authority".to_string()];
        let out = crate::security::refusal_recovery::try_recover_multi(
            &provider,
            &req,
            trusted_origin(),
            "Against my guidelines.",
            &disabled,
            None,
            0,
            3,
        )
        .await
        .unwrap();
        match out {
            RecoveryOutcome::NotRecoverable { cause } => {
                assert_eq!(cause, RefusalCause::SafetyPolicy);
            }
            _ => panic!("disabled truthful retry must not fall through"),
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
            trusted_origin(),
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
