//! End-to-end orchestrator for the 6-stage profile pipeline.
//!
//! Stages 1-6 ship individually; this module wires them together so a
//! single call drives the whole `profile_learn.yaml`:
//!
//! ```text
//!   window_extract → window_attribute → extract (LLM) →
//!   validate → claim_guard (H1+H2+H5+M1+M2) → apply
//! ```
//!
//! On reject at any stage, a `PROFILE_DELTA_BLOCKED` WAL frame records
//! the reason; the pipeline returns the outcome without partial-state.
//!
//! `run_pipeline` is `async` because stage 3 (extract) hits the provider.
//! Every other stage is pure-function over typed structs.
//!
//! ADV-10 Slice A: Stage 3 may return
//! `Ok(PipelineRun::Skipped(PipelineSkip::QuotaExceeded { .. }))` when the
//! provider returns HTTP 429, so a rate-limited provider does not surface
//! as a generic `Err`. The graceful skip emits a
//! `0xB9 PROFILE_EXTRACT_SKIPPED` audit frame and the caller treats it as
//! "try again later" rather than a real failure.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::profile::apply::{ApplyOutcome, apply_delta, record_blocked};
use crate::profile::claim_guard::{GuardOutcome, GuardReason, ProfileClaimGuard};
use crate::profile::delta::ProfileDelta;
use crate::profile::extension_registry::TypedExtensionRegistry;
use crate::profile::extract::extract as extract_delta;
use crate::profile::timestamp_check::TimestampPolicy;
use crate::profile::validate::{DroppedClaim, validate};
use crate::profile::window_attribute::attribute_segments;
use crate::profile::window_extract::extract_window;
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

/// COR-33: how `run_pipeline` reaches its `views.db` connection.
///
/// The LLM extraction stage (`extract_delta`) does NOT touch the connection —
/// it works on the in-memory attributed window — so for the daemon channel
/// path the shared `views.db` lock must NOT be held across that `.await`
/// (holding it serialized every channel's post-reply profile pipeline on the
/// DB mutex while one was doing its seconds-long LLM call — CR-010 / A-15).
/// `run_pipeline` therefore takes a `PipelineConn` and acquires the connection
/// only for the brief synchronous DB stages (window read, redactions read,
/// apply write), releasing it around the LLM call.
///
/// `Owned` callers (interactive chat / CLI / tests) hold an exclusive
/// `&mut Connection`; `lock()` is a zero-cost reborrow. `Shared` (the daemon
/// channel pipeline) locks the per-process `views.db` mutex per DB stage. A
/// per-call connection is deliberately NOT used for the shared path:
/// `replay_once` (WAL→views) runs first and concurrent connections would race
/// on the replay offset — the shared connection serializes replay + writes.
pub enum PipelineConn<'a> {
    Owned(&'a mut Connection),
    Shared(&'a std::sync::Arc<tokio::sync::Mutex<Connection>>),
}

/// Short-lived guard over the `views.db` connection for ONE synchronous DB
/// stage of `run_pipeline`. Dropping it releases the shared mutex (a no-op for
/// `Owned`). MUST be dropped before any non-DB `.await` (esp. the LLM extract).
enum PipelineConnGuard<'a> {
    Owned(&'a mut Connection),
    Shared(tokio::sync::MutexGuard<'a, Connection>),
}

impl PipelineConn<'_> {
    async fn lock(&mut self) -> PipelineConnGuard<'_> {
        match self {
            PipelineConn::Owned(c) => PipelineConnGuard::Owned(c),
            PipelineConn::Shared(arc) => PipelineConnGuard::Shared(arc.lock().await),
        }
    }
}

impl PipelineConnGuard<'_> {
    fn as_mut(&mut self) -> &mut Connection {
        match self {
            PipelineConnGuard::Owned(c) => c,
            PipelineConnGuard::Shared(g) => g,
        }
    }
}

/// Why the pipeline aborted partway through.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PipelineSkip {
    #[error("conversation window had no user-speech segments")]
    NoUserSpeechInWindow,
    #[error("validator rejected delta with whole-delta error: {0}")]
    ValidateWholeDeltaError(String),
    #[error("guard rejected delta: {0}")]
    GuardRejected(String),
    /// ADV-03 item 4 Phase 5: Stage-5b approval_gate parked the delta
    /// in `idx_profile_pending` because the operator runs in daemon
    /// mode (no tty). Resolve via `neoth profile approve <id>`.
    #[error("approval_gate queued delta {0} for operator review")]
    ApprovalQueued(String),
    /// ADV-03 item 4 Phase 5: operator answered "no" at the tty
    /// confirm prompt. The delta is dropped + a 0xB7 audit frame
    /// was emitted.
    #[error("operator declined delta at approval prompt")]
    ApprovalDeclined,
    /// ADV-10 Slice A (Session 28g): the Stage 3 LLM call returned
    /// HTTP 429 (rate-limit). Surfaced as a typed skip so the caller
    /// can tell "provider rate-limited; try later" apart from "the
    /// provider gave a real error" — pre-fix this surfaced as a
    /// generic `Err` and the operator lost the provider + retry signal.
    /// A `0xB9 PROFILE_EXTRACT_SKIPPED` audit frame was emitted.
    ///
    /// The Display message intentionally omits `retry_after_secs` (typed
    /// `Option<u64>` has no Display impl; Debug would leak Rust syntax
    /// like `Some(42)` into operator-facing log lines via `%reason`). The
    /// structured field stays available to callers + lives in the WAL
    /// frame payload.
    #[error("profile extraction skipped — provider `{provider}` rate-limited (HTTP 429)")]
    QuotaExceeded {
        /// `Provider::name()` of the throttled adapter (e.g. `"openai_api"`).
        provider: String,
        /// `Retry-After` seconds when the 429 carried that header; `None`
        /// when the dispatcher fell back to the default backoff. Capped
        /// at `quota::MAX_BACKOFF` (24h) to defend the WAL + downstream
        /// schedulers against adversarial response headers.
        retry_after_secs: Option<u64>,
    },
}

/// Outcome of one end-to-end run.
#[derive(Clone, Debug, PartialEq)]
pub enum PipelineRun {
    /// Pipeline completed and applied (possibly empty) claims.
    Applied {
        outcome: ApplyOutcome,
        validated_dropped: Vec<DroppedClaim>,
    },
    /// Pipeline aborted with the given reason. A `PROFILE_DELTA_BLOCKED`
    /// audit frame was written for guard rejections.
    Skipped(PipelineSkip),
}

/// Drive the full pipeline for a single trigger event id.
///
/// `turns_back` controls how many prior turn-pairs the window covers
/// (spec default = 2). `extensions` lets the operator opt into typed
/// extension categories beyond the base taxonomy. `now_unix` is taken
/// as a parameter so tests pin daily-counter rollovers.
// TODO(profile follow-up): extract a `RunPipelineInputs` config struct
// so the 9-arg signature shrinks; the wide signature mirrors the
// pipeline's stage inputs 1:1 and is stable across callers.
#[allow(clippy::too_many_arguments)]
/// ADV-07: drop every `operator_preferences` claim from a freshly
/// extracted delta (applied on mirror-recovery turns). Returns the number
/// of claims removed. Pure — unit-testable without the full pipeline /
/// guard / extension registry.
fn drop_mirror_categories(delta: &mut ProfileDelta) -> usize {
    let before = delta.claims.len();
    delta
        .claims
        .retain(|c| !c.field.starts_with("operator_preferences"));
    before - delta.claims.len()
}

// Pipeline orchestrator — the staged dependencies (conn, writer,
// provider, guard, registry, gate ctx, mirror flag) are each distinct +
// not naturally groupable into a config struct without obscuring the
// call sites. ADV-07 added the 10th arg; an args-struct refactor is
// tracked as a separate cleanup, not worth churning every call site now.
#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline(
    mut conn: PipelineConn<'_>,
    writer: &WalWriterHandle,
    provider: &dyn Provider,
    trigger_event_id: i64,
    turns_back: u32,
    guard: &ProfileClaimGuard,
    extensions: &TypedExtensionRegistry,
    now_unix: u64,
    // ADV-03 item 4 Phase 5 (Session 24): when `Some`, route the
    // post-Stage-5 delta through `approval_gate` before apply. When
    // `None`, behaviour is identical to pre-Phase-5 — every guarded
    // delta proceeds straight to Stage 6 (existing callers).
    gate_ctx: Option<ApprovalGateContext<'_>>,
    // ADV-07 (Session 28c): true when THIS turn's reply came from the
    // mirror refusal-recovery path (a refusal was auto-reframed + retried).
    // On such turns the `operator_preferences` the extractor infers are
    // about the REFRAMING, not the operator (self-amplifying loop "operator
    // values limitation-reflection"). When true, drop every
    // `operator_preferences` claim post-extract; other categories extract
    // normally.
    skip_mirror_categories: bool,
) -> Result<PipelineRun> {
    // V10-07 H3 privacy guard: profile extraction sees the operator's
    // full conversation window — routing that through a cloud provider
    // hands raw private speech to a third-party vendor. Per the v1.1
    // §A1 + GA blocker V10-07 goal "Gemini never sees raw
    // conversation", the default extraction path should use local_qwen.
    // When the operator explicitly overrides to a cloud provider we
    // surface a one-shot WARN naming the V10-07 issue so the privacy
    // posture stays auditable. The pipeline does NOT refuse — operators
    // running on hardware without local inference (no GPU + no CPU
    // budget for Qwen3-4B) still need a path; the warn is the
    // observability hook, not a gate.
    warn_if_cloud_provider_used_for_profile_extraction_once(provider.name());

    // SPEC-04 (Session 28) — provider-target audit frame. Records
    // which provider is about to see the operator's raw conversation
    // window + whether it's on-device. The warn above is ephemeral
    // (one-shot per process); this frame is the DURABLE per-turn
    // record so a privacy-posture regression stays visible in the
    // audit chain even if the operator later flips the config back.
    // Best-effort: an emit failure must NOT abort extraction (the
    // privacy floor is enforced upstream by from_config_for_learn,
    // not by this audit frame). Emitted BEFORE Stage 3 so a crash
    // mid-extract still leaves the "we were about to use provider X"
    // record.
    emit_extract_target_audit(writer, provider.name(), trigger_event_id, now_unix as i64).await;

    // Stage 1 — window_extract. COR-33: lock the shared conn only for this
    // synchronous read, then release it before the LLM extract below.
    let window = {
        let mut g = conn.lock().await;
        extract_window(g.as_mut(), trigger_event_id, turns_back)
            .context("pipeline stage 1: window_extract")?
    };

    // Stage 2 — window_attribute.
    let attributed = attribute_segments(&window);
    if !attributed.has_user_speech_segments() {
        return Ok(PipelineRun::Skipped(PipelineSkip::NoUserSpeechInWindow));
    }

    // Stage 3 — extract (LLM call). Short-circuits if no eligible
    // segments survive attribution.
    //
    // ADV-10 Slice A: when the provider returns HTTP 429 (rate-limit), do
    // NOT propagate a generic error — that would lose the provider +
    // `Retry-After` signal and surface as a tracing::warn in the caller.
    // Downcast `QuotaError` from the anyhow chain (anyhow walks
    // `source()`; the same pattern is used in `cli::chat`'s three
    // provider-error sites), emit a `0xB9 PROFILE_EXTRACT_SKIPPED` audit
    // frame, and return `Ok(Skipped)` so the cron / chat-tail caller
    // treats this as a clean "try again later" outcome.
    let mut delta: ProfileDelta = match extract_delta(provider, &attributed).await {
        Ok(d) => d,
        Err(e) => {
            if let Some(qe) = e.downcast_ref::<crate::providers::quota::QuotaError>() {
                // Cap `retry_after` at `MAX_BACKOFF` (24h) to match what
                // `QuotaTracker::record_429` enforces — without the cap an
                // adversarial server sending `Retry-After: 99999999` would
                // land verbatim in the durable WAL + the Skip variant
                // while the in-process tracker quietly clamps it. Apply
                // the cap once at the emit site so the audit chain, the
                // returned `PipelineSkip`, and the tracker all agree.
                let retry_after_secs = qe
                    .retry_after
                    .map(|d| d.min(crate::providers::quota::MAX_BACKOFF).as_secs());
                let payload = match serde_json::to_vec(&serde_json::json!({
                    "provider": qe.provider,
                    "retry_after_secs": retry_after_secs,
                    "trigger_event_id": trigger_event_id,
                    "ts_unix": now_unix,
                })) {
                    Ok(p) => p,
                    Err(emit_err) => {
                        // Best-effort: a serialize failure on primitive
                        // fields is effectively impossible, but mirror the
                        // explicit-match pattern `emit_extract_target_audit`
                        // uses so a future field addition can't silently
                        // truncate to an empty payload via
                        // `unwrap_or_default()`.
                        tracing::warn!(
                            error = %emit_err,
                            "serialise PROFILE_EXTRACT_SKIPPED payload failed — audit frame skipped"
                        );
                        return Ok(PipelineRun::Skipped(PipelineSkip::QuotaExceeded {
                            provider: qe.provider.to_string(),
                            retry_after_secs,
                        }));
                    }
                };
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_PROFILE_EXTRACT_SKIPPED,
                    &payload,
                )
                .build();
                if let Err(emit_err) = writer.append(header, payload).await {
                    tracing::warn!(
                        error = %emit_err,
                        "PROFILE_EXTRACT_SKIPPED WAL append failed (best-effort audit frame)"
                    );
                }
                tracing::warn!(
                    provider = qe.provider,
                    retry_after_secs = ?retry_after_secs,
                    "profile extraction skipped — provider returned 429"
                );
                return Ok(PipelineRun::Skipped(PipelineSkip::QuotaExceeded {
                    provider: qe.provider.to_string(),
                    retry_after_secs,
                }));
            }
            return Err(e).context("pipeline stage 3: profile.extract");
        }
    };

    // ADV-07: on a mirror-recovery turn, drop operator_preferences claims
    // before validation so the reframing-induced "preferences" never reach
    // idx_profile (closes the self-amplifying feedback loop). The reroute
    // itself stays auditable via the 0x19 REFUSAL_REROUTED frame.
    if skip_mirror_categories {
        let dropped = drop_mirror_categories(&mut delta);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "ADV-07: dropped operator_preferences claims on mirror-recovery turn"
            );
        }
    }

    // Stage 4 — validate. Whole-delta errors abort with no audit
    // (those are misuse, not adversarial); per-claim drops fold into
    // the outcome so the operator can see what the validator filtered.
    let validated = match validate(delta, &attributed) {
        Ok(v) => v,
        Err(e) => {
            return Ok(PipelineRun::Skipped(PipelineSkip::ValidateWholeDeltaError(
                e.to_string(),
            )));
        }
    };

    // Stage 5 — claim_guard (H1+H2+H5+M1+M2). Pull live redactions
    // from idx_profile_redactions; derive the timestamp policy from the
    // window's anchor range.
    let redactions = {
        let mut g = conn.lock().await;
        load_active_redactions(g.as_mut())?
    };
    let policy = TimestampPolicy::from_window(&attributed, 1)
        // Empty window fallback — already guarded by stage 2 check, but
        // be defensive.
        .unwrap_or(TimestampPolicy {
            window_oldest_unix: 0,
            window_newest_unix: i64::MAX,
            padding_days: 0,
        });

    let outcome = guard.check_all(
        validated.delta.clone(),
        &attributed,
        &redactions,
        extensions,
        &policy,
        now_unix,
    );

    let guarded = match outcome {
        GuardOutcome::Accepted(d) => d,
        GuardOutcome::Rejected {
            reason,
            blocked_delta_hash,
        } => {
            // Audit-only frame so the operator can grep `neoth wal show
            // --type 0xB4` and see why the delta was rejected.
            let hex_hash = hex_encode(&blocked_delta_hash);
            let reason_str = reason_to_str(&reason);
            record_blocked(
                writer,
                &validated.delta.extraction_id,
                &reason_str,
                &hex_hash,
                &validated.delta.guard_version,
                now_unix as i64,
            )
            .await?;
            return Ok(PipelineRun::Skipped(PipelineSkip::GuardRejected(
                reason_str,
            )));
        }
    };

    // Stage 5b — approval_gate (ADV-03 item 4 Phase 5). When the
    // caller passes an `ApprovalGateContext`, route the guarded
    // delta through the operator-confirmation gate before apply.
    // Backward-compat: legacy `run_pipeline` (no context) always
    // bypasses the gate and behaves exactly as before.
    if let Some(ctx) = gate_ctx {
        use crate::profile::approval_gate::{ApprovalOutcome, approval_gate};
        let outcome = {
            let mut g = conn.lock().await;
            approval_gate(
                &guarded,
                ctx.config,
                ctx.autonomy,
                ctx.is_tty,
                g.as_mut(),
                ctx.confirm_fn,
                now_unix,
            )
            .context("pipeline stage 5b: approval_gate")?
        };
        match outcome {
            ApprovalOutcome::Approved => {
                // fall through to Stage 6
            }
            ApprovalOutcome::Queued { extraction_id } => {
                return Ok(PipelineRun::Skipped(PipelineSkip::ApprovalQueued(
                    extraction_id,
                )));
            }
            ApprovalOutcome::Declined => {
                return Ok(PipelineRun::Skipped(PipelineSkip::ApprovalDeclined));
            }
        }
    }

    // Stage 6 — apply. Idempotent on extraction_id. COR-33: re-lock for the
    // write phase (the lock was released around the LLM extract above).
    let apply_outcome = {
        let mut g = conn.lock().await;
        apply_delta(g.as_mut(), writer, &guarded, now_unix as i64)
            .await
            .context("pipeline stage 6: profile.apply")?
    };

    Ok(PipelineRun::Applied {
        outcome: apply_outcome,
        validated_dropped: validated.dropped,
    })
}

/// ADV-03 item 4 Phase 5: context passed to `run_pipeline_with_gate`
/// so Stage 5b (`approval_gate`) can route the post-guard delta. The
/// `confirm_fn` closure isolates the actual prompt — production
/// callers pass a `dialoguer::Confirm::interact()`; tests pass a
/// canned yes/no.
pub struct ApprovalGateContext<'a> {
    pub config: &'a crate::config::ProfileConfig,
    pub autonomy: crate::permissions::AutonomyLevel,
    pub is_tty: bool,
    pub confirm_fn: Box<dyn FnOnce(&ProfileDelta) -> bool + 'a>,
}

/// Pull the active redacted field names from `idx_profile_redactions`.
/// V10-07 H3 privacy guard once-flag. Fires at most one WARN per
/// daemon run regardless of how many profile-extraction passes use a
/// cloud provider — a busy daemon that runs the pipeline on every
/// inbound burst would otherwise spam the journal.
static V10_07_PROVIDER_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Returns true if the provider name (`Provider::name()`) is a local
/// inference path. Local providers see the operator's conversation but
/// the data stays on-device — no privacy concern under H3. Delegates to
/// the canonical [`crate::providers::is_local_provider`] so the
/// local-provider set lives in exactly one place (GR-17).
fn is_local_inference_provider(name: &str) -> bool {
    crate::providers::is_local_provider(name)
}

/// SPEC-04 (Session 28) — stable wire label for the `target` field in
/// the `PROFILE_EXTRACT_TARGET` audit frame. `"local"` when the
/// provider runs on-device (no privacy concern under H3), `"cloud"`
/// otherwise. Pure-fn so the local/cloud decision is unit-testable
/// without spinning up a WAL writer; the labels are the operator-
/// facing strings `neoth privacy audit` + WAL consumers grep, so a
/// rename must be deliberate.
///
/// `pub(crate)` so the main-chat + n8n PROVIDER_REQUEST emit sites tag
/// each request with the same `local`/`cloud` label (SPEC-04 audit-pair).
pub(crate) fn extract_target_label(provider_name: &str) -> &'static str {
    if is_local_inference_provider(provider_name) {
        "local"
    } else {
        "cloud"
    }
}

/// SPEC-04 (Session 28) — emit one `PROFILE_EXTRACT_TARGET` (0x2E)
/// audit frame recording the provider + its on/off-device
/// classification for this extraction turn. Best-effort: a WAL write
/// failure logs a warn + returns (never aborts extraction — the
/// privacy floor is enforced upstream, this frame is the audit trail
/// not the gate). Target classification reuses
/// [`is_local_inference_provider`] so the audit + the one-shot warn
/// agree on what counts as "local".
async fn emit_extract_target_audit(
    writer: &WalWriterHandle,
    provider_name: &str,
    trigger_event_id: i64,
    now_unix: i64,
) {
    let target = extract_target_label(provider_name);
    let payload = match serde_json::to_vec(&serde_json::json!({
        "trigger_event_id": trigger_event_id,
        "provider": provider_name,
        "target": target,
        "ts_unix": now_unix,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialise PROFILE_EXTRACT_TARGET payload failed; skipping audit frame");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROFILE_EXTRACT_TARGET,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "append PROFILE_EXTRACT_TARGET frame failed (non-fatal)");
    }
}

/// One-shot WARN when `run_pipeline` is called with a cloud provider.
/// Honest no-op for local providers. Test-only reset + flag-read
/// accessors keep the warn behaviour testable without touching the
/// production atomic.
fn warn_if_cloud_provider_used_for_profile_extraction_once(provider_name: &str) {
    use std::sync::atomic::Ordering;
    if is_local_inference_provider(provider_name) {
        return;
    }
    if V10_07_PROVIDER_WARNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tracing::warn!(
            target: "profile",
            provider = provider_name,
            "V10-07 H3 privacy posture: profile extraction is using a cloud \
             provider — the operator's raw conversation window is being sent \
             off-device for fact extraction. The intended posture for v1.0 GA \
             is `local_qwen` (Qwen3-4B-INT4) so private speech never leaves \
             the operator's machine. Set `inference.profile_provider: \
             local_qwen` in freedom.yaml (or run the wizard step 5b) to \
             switch. Pipeline continues — this is observability, not a gate."
        );
    }
}

/// Test-only reset for the V10-07 warn flag.
#[cfg(test)]
pub(crate) fn reset_v10_07_warned_flag_for_test() {
    V10_07_PROVIDER_WARNED.store(false, std::sync::atomic::Ordering::Release);
}

#[cfg(test)]
pub(crate) fn v10_07_warned_flag_for_test() -> bool {
    V10_07_PROVIDER_WARNED.load(std::sync::atomic::Ordering::Acquire)
}

fn load_active_redactions(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT field FROM idx_profile_redactions \
             WHERE revoked_at IS NULL AND never_recreate = 1",
        )
        .context("prepare redaction lookup")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect active redactions")?;
    Ok(rows)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn reason_to_str(r: &GuardReason) -> String {
    r.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use crate::profile::claim_guard::GuardConfig;
    use crate::providers::{Completion, Provider, Request};
    use crate::wal::events::EVENT_TYPE_RAW_TEXT;
    use crate::wal::writer::spawn;
    use async_trait::async_trait;
    use rusqlite::params;
    use std::time::Duration;
    use tempfile::tempdir;

    struct LlmMock {
        reply: String,
    }

    #[async_trait]
    impl Provider for LlmMock {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                text: self.reply.clone(),
                model: "mock-1".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    // COR-33: a provider whose `complete` (the LLM extract stage) signals it has
    // entered, then blocks until released — used to prove run_pipeline does NOT
    // hold the views.db lock across the LLM call.
    struct BlockingLlmMock {
        reply: String,
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Semaphore>,
    }

    #[async_trait]
    impl Provider for BlockingLlmMock {
        fn name(&self) -> &'static str {
            "blocking-mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            self.entered.notify_one();
            let _permit = self.release.acquire().await;
            Ok(Completion {
                text: self.reply.clone(),
                model: "mock-1".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    fn insert_episode(conn: &Connection, event_id: i64, et: u8, text: &str, ts_ns: i64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, '')",
            params![event_id, et as i64, ts_ns, text],
        )
        .unwrap();
    }

    async fn setup() -> (
        tempfile::TempDir,
        Connection,
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let (writer, join) = spawn(dir.path().join("seg.wal")).unwrap();
        (dir, conn, writer, join)
    }

    fn valid_llm_reply_with_today_date() -> String {
        // Plain string-valued claim — no embedded date — so the M1
        // timestamp gate has nothing to flag. The window's anchor
        // bounds are still enforced because M1 only triggers when a
        // claim VALUE carries a date; an absence-of-date claim passes
        // trivially.
        r#"{
          "extraction_id": "ext-test-1",
          "conversation_hash": "abc",
          "claims": [
            {
              "field": "identity.location",
              "value_json": "Berlin",
              "confidence": 0.9,
              "reasoning": "operator stated location",
              "evidence_event_ids": [10]
            }
          ],
          "contradictions": []
        }"#
        .to_string()
    }

    #[test]
    fn adv07_drop_mirror_categories_removes_only_operator_preferences() {
        use crate::profile::delta::{ProfileDelta, RawClaim};
        let mut delta = ProfileDelta {
            claims: vec![
                RawClaim {
                    field: "identity.location".into(),
                    value_json: serde_json::json!("Berlin"),
                    confidence: 0.9,
                    reasoning: String::new(),
                    evidence_event_ids: vec![],
                },
                RawClaim {
                    field: "operator_preferences.tone".into(),
                    value_json: serde_json::json!("blunt"),
                    confidence: 0.8,
                    reasoning: String::new(),
                    evidence_event_ids: vec![],
                },
                RawClaim {
                    field: "operator_preferences.format".into(),
                    value_json: serde_json::json!("terse"),
                    confidence: 0.8,
                    reasoning: String::new(),
                    evidence_event_ids: vec![],
                },
            ],
            ..Default::default()
        };
        let dropped = drop_mirror_categories(&mut delta);
        assert_eq!(dropped, 2, "both operator_preferences claims dropped");
        assert_eq!(delta.claims.len(), 1);
        assert_eq!(delta.claims[0].field.as_str(), "identity.location");
    }

    #[test]
    fn adv07_drop_mirror_categories_noop_without_operator_preferences() {
        use crate::profile::delta::{ProfileDelta, RawClaim};
        let mut delta = ProfileDelta {
            claims: vec![RawClaim {
                field: "skills.rust".into(),
                value_json: serde_json::json!("expert"),
                confidence: 0.9,
                reasoning: String::new(),
                evidence_event_ids: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(drop_mirror_categories(&mut delta), 0);
        assert_eq!(delta.claims.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_runs_end_to_end_and_writes_idx_profile_row() {
        let (_dir, mut conn, writer, join) = setup().await;
        // 2026-05-15 unix = 1778803200; convert to ns for ts_ns.
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,  // ADV-03 Phase 5: gate context unused in this test
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        match out {
            PipelineRun::Applied { outcome, .. } => {
                assert_eq!(outcome.claims_applied, 1);
            }
            PipelineRun::Skipped(s) => panic!("expected Applied, got Skipped({s})"),
        }

        // idx_profile now has one row for identity.location.
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile WHERE field = 'identity.location'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn cor33_shared_conn_lock_released_during_llm_extract() {
        // COR-33: with a Shared views.db connection, run_pipeline must release the
        // mutex around the LLM extract (which doesn't touch the conn) so
        // concurrent channel pipelines don't serialize on the DB lock for the
        // whole seconds-long turn. Proof: block the provider mid-extract and
        // assert the shared lock is acquirable while the LLM is in flight. With
        // the pre-fix code (lock held across run_pipeline) this lock would block
        // until the LLM finished and the 2s timeout would trip.
        let (_dir, conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(conn));

        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let provider = BlockingLlmMock {
            reply: valid_llm_reply_with_today_date(),
            entered: std::sync::Arc::clone(&entered),
            release: std::sync::Arc::clone(&release),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();

        // run_pipeline's future is !Send (it holds the rusqlite connection
        // across awaits — that's why the daemon runs it under block_in_place,
        // not tokio::spawn), so drive it concurrently with the lock-probe on the
        // SAME task via join! rather than spawning.
        let pipeline_fut = run_pipeline(
            PipelineConn::Shared(&shared),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,
            false,
        );
        let probe_fut = async {
            // Block until the pipeline has entered the LLM extract.
            entered.notified().await;
            // The views.db lock MUST be free while the LLM call is in flight.
            let acquired = tokio::time::timeout(Duration::from_secs(2), shared.lock()).await;
            assert!(
                acquired.is_ok(),
                "COR-33: views.db lock must be released during the LLM extract"
            );
            drop(acquired);
            // Release the LLM so the pipeline re-locks for apply and finishes.
            release.add_permits(1);
        };
        let (out, ()) = tokio::join!(pipeline_fut, probe_fut);
        assert!(
            matches!(out.unwrap(), PipelineRun::Applied { .. }),
            "COR-33: shared-conn pipeline must apply post-LLM"
        );

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_skips_when_window_has_no_user_speech() {
        let (_dir, mut conn, writer, join) = setup().await;
        // Insert only PROVIDER_RESPONSE rows → all tool_output.
        insert_episode(
            &conn,
            10,
            crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
            "Sure, here is the answer.",
            1,
        );

        let provider = LlmMock {
            reply: "should not be called".into(),
        };
        let guard = ProfileClaimGuard::default();
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            100,
            None,  // ADV-03 Phase 5: gate context unused in this test
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        assert!(matches!(
            out,
            PipelineRun::Skipped(PipelineSkip::NoUserSpeechInWindow)
        ));
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_skips_when_field_is_redacted() {
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);
        // Pre-register a redaction for identity.location.
        crate::profile::redaction::add(&conn, "identity.location", true, None, "operator", 1)
            .unwrap();

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::default();
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,  // ADV-03 Phase 5: gate context unused in this test
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        match out {
            PipelineRun::Skipped(PipelineSkip::GuardRejected(reason)) => {
                assert!(reason.contains("redacted"), "got {reason}");
            }
            _ => panic!("expected GuardRejected on redacted field, got {out:?}"),
        }

        // idx_profile is empty — no rows applied.
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_idempotent_on_replay() {
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::default();
        let extensions = TypedExtensionRegistry::default();
        let _ = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,  // ADV-03 Phase 5: gate context unused in this test
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        let out2 = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,  // ADV-03 Phase 5: gate context unused in this test
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        match out2 {
            PipelineRun::Applied { outcome, .. } => {
                assert_eq!(outcome.claims_applied, 0);
                assert!(outcome.idempotent_skip);
            }
            _ => panic!("expected idempotent Applied on second run"),
        }
        drop(writer);
        let _ = join.await;
    }

    #[test]
    fn hex_encode_zero_pads_each_byte() {
        assert_eq!(hex_encode(&[0x0a, 0xff, 0x00]), "0aff00");
    }

    // ── V10-07 H3 privacy guard ───────────────────────────────────────

    #[test]
    fn local_providers_do_not_set_v10_07_warn_flag() {
        reset_v10_07_warned_flag_for_test();
        for name in ["local_qwen", "local_ouro"] {
            warn_if_cloud_provider_used_for_profile_extraction_once(name);
            assert!(
                !v10_07_warned_flag_for_test(),
                "local provider {name} must NOT trip the cloud-provider warn"
            );
        }
    }

    #[test]
    fn cloud_provider_sets_v10_07_warn_flag_once() {
        reset_v10_07_warned_flag_for_test();
        warn_if_cloud_provider_used_for_profile_extraction_once("gemini_api");
        assert!(v10_07_warned_flag_for_test());
        // Second call must NOT reset / re-toggle — CAS-once contract.
        let first = v10_07_warned_flag_for_test();
        warn_if_cloud_provider_used_for_profile_extraction_once("openai_api");
        assert_eq!(v10_07_warned_flag_for_test(), first);
        reset_v10_07_warned_flag_for_test();
    }

    #[test]
    fn is_local_provider_classifies_inference_paths_correctly() {
        assert!(is_local_inference_provider("local_qwen"));
        assert!(is_local_inference_provider("local_ouro"));
        assert!(!is_local_inference_provider("claude_cli"));
        assert!(!is_local_inference_provider("openai_api"));
        assert!(!is_local_inference_provider("gemini_api"));
        assert!(!is_local_inference_provider("aws_bedrock"));
        assert!(!is_local_inference_provider("azure_openai"));
    }

    // ── ADV-03 item 4 Phase 8: gate-aware integration tests ─────────────

    #[tokio::test]
    async fn pipeline_with_gate_queues_when_tty_absent() {
        // Daemon-mode integration: full pipeline → claim_guard → gate.
        // Operator runs in `serve` mode (no tty), require_approval=true,
        // autonomy=Standard. The delta must land in idx_profile_pending
        // + the run returns PipelineSkip::ApprovalQueued.
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();

        let mut cfg = crate::config::ProfileConfig::default();
        cfg.require_approval = true;
        let ctx = ApprovalGateContext {
            config: &cfg,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            is_tty: false,
            // confirm closure must NEVER fire in tty-less mode; panic
            // if it does to surface the wiring bug loudly.
            confirm_fn: Box::new(|_| panic!("confirm must not fire without tty")),
        };
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            Some(ctx),
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        match out {
            PipelineRun::Skipped(PipelineSkip::ApprovalQueued(id)) => {
                assert!(!id.is_empty());
                // Pending row exists in the DB.
                let pending = crate::profile::approval_gate::list_pending(&conn, 10).unwrap();
                assert_eq!(pending.len(), 1);
                assert_eq!(pending[0].extraction_id, id);
            }
            other => panic!("expected ApprovalQueued, got {other:?}"),
        }
        // No idx_profile row written — the apply path was bypassed.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_profile WHERE superseded_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "apply_delta MUST NOT run on Queued outcome");
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_with_gate_applies_when_tty_confirm_yes() {
        // Tty integration: operator approves → full flow proceeds to
        // Stage 6 apply_delta, idx_profile row lands, no pending row.
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();

        let mut cfg = crate::config::ProfileConfig::default();
        cfg.require_approval = true;
        let ctx = ApprovalGateContext {
            config: &cfg,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            is_tty: true,
            confirm_fn: Box::new(|_delta| true), // operator says yes
        };
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            Some(ctx),
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        match out {
            PipelineRun::Applied { outcome, .. } => {
                assert_eq!(outcome.claims_applied, 1);
            }
            other => panic!("expected Applied on tty-yes, got {other:?}"),
        }
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_with_gate_declines_when_tty_confirm_no() {
        // Tty integration: operator declines → PipelineSkip::ApprovalDeclined,
        // no idx_profile row, no pending row (decline drops the delta).
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();

        let mut cfg = crate::config::ProfileConfig::default();
        cfg.require_approval = true;
        let ctx = ApprovalGateContext {
            config: &cfg,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            is_tty: true,
            confirm_fn: Box::new(|_delta| false), // operator says no
        };
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            Some(ctx),
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        assert!(matches!(
            out,
            PipelineRun::Skipped(PipelineSkip::ApprovalDeclined)
        ));
        // No idx_profile row, no pending row — operator rejected the delta.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let pending = crate::profile::approval_gate::list_pending(&conn, 10).unwrap();
        assert_eq!(pending.len(), 0);
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn pipeline_with_gate_full_autonomy_bypasses_confirm() {
        // AutonomyLevel::Full skips the gate regardless of
        // require_approval. Confirm closure must never fire; apply
        // proceeds straight through.
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();

        let mut cfg = crate::config::ProfileConfig::default();
        cfg.require_approval = true;
        let ctx = ApprovalGateContext {
            config: &cfg,
            autonomy: crate::permissions::AutonomyLevel::Full,
            is_tty: true,
            confirm_fn: Box::new(|_| panic!("Full autonomy must skip confirm")),
        };
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            Some(ctx),
            false, // ADV-07: not a mirror-recovery turn
        )
        .await
        .unwrap();
        assert!(matches!(out, PipelineRun::Applied { .. }));
        drop(writer);
        let _ = join.await;
    }

    // ── ADV-10 Slice A: HTTP 429 → graceful Stage-3 skip + WAL emit ────

    struct QuotaErrorMock {
        retry_after_secs: Option<u64>,
    }

    #[async_trait]
    impl Provider for QuotaErrorMock {
        fn name(&self) -> &'static str {
            "quota_mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            // Return the QuotaError directly — wrapped through the same
            // `.context()` chain extract_delta uses in production so the
            // test exercises the real anyhow-chain downcast path.
            Err(anyhow::Error::from(crate::providers::quota::QuotaError {
                provider: "quota_mock",
                retry_after: self.retry_after_secs.map(Duration::from_secs),
                body: String::new(),
            }))
            .context("simulated 429 from provider")
        }
    }

    #[tokio::test]
    async fn pipeline_skips_and_emits_0xb9_when_provider_returns_429() {
        let (dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);

        let provider = QuotaErrorMock {
            retry_after_secs: Some(42),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,
            false,
        )
        .await
        .expect("a QuotaError must be a clean Skipped, not a propagated Err");

        match out {
            PipelineRun::Skipped(PipelineSkip::QuotaExceeded {
                provider,
                retry_after_secs,
            }) => {
                assert_eq!(provider, "quota_mock");
                assert_eq!(retry_after_secs, Some(42));
            }
            other => panic!("expected Skipped(QuotaExceeded), got {other:?}"),
        }

        // No idx_profile row was written — the pipeline aborted at Stage 3.
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "no claim should have been applied");

        drop(writer);
        let _ = join.await;

        // The 0xB9 PROFILE_EXTRACT_SKIPPED audit frame must be on disk —
        // SC-01a's emit-site guard requires every defined event to be
        // emitted by something, and this is the (only) emit site.
        let seg = std::fs::read(dir.path().join("seg.wal")).unwrap();
        let body = &seg[crate::wal::segment_header::parse_segment_header(&seg)
            .unwrap()
            .header_len()..];
        let mut cursor = 0usize;
        let mut found_skip = false;
        while cursor < body.len() {
            let Ok(dec) = crate::wal::frame::decode_frame(&body[cursor..]) else {
                break;
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROFILE_EXTRACT_SKIPPED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["provider"], "quota_mock");
                assert_eq!(v["retry_after_secs"], 42);
                assert_eq!(v["trigger_event_id"], 10);
                found_skip = true;
                break;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert!(
            found_skip,
            "0xB9 PROFILE_EXTRACT_SKIPPED frame must be in the WAL"
        );
    }

    #[tokio::test]
    async fn pipeline_skips_with_none_retry_when_429_carries_no_header() {
        // Pin that a 429 without `Retry-After` round-trips as
        // `retry_after_secs: None` BOTH in the `Skip` variant AND on
        // disk — the WAL frame must serialize JSON `null` (not `0`, not
        // omitted) so downstream tooling can tell "no header sent" from
        // "header said 0 seconds".
        let (dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);
        let provider = QuotaErrorMock {
            retry_after_secs: None,
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,
            false,
        )
        .await
        .unwrap();
        match out {
            PipelineRun::Skipped(PipelineSkip::QuotaExceeded {
                retry_after_secs, ..
            }) => assert_eq!(retry_after_secs, None),
            other => panic!("expected Skipped(QuotaExceeded), got {other:?}"),
        }
        drop(writer);
        let _ = join.await;

        // Walk the on-disk WAL to confirm the `None` case serialises as
        // JSON `null` — the regression guard the prior test missed.
        let seg = std::fs::read(dir.path().join("seg.wal")).unwrap();
        let body = &seg[crate::wal::segment_header::parse_segment_header(&seg)
            .unwrap()
            .header_len()..];
        let mut cursor = 0usize;
        let mut found_skip = false;
        while cursor < body.len() {
            let Ok(dec) = crate::wal::frame::decode_frame(&body[cursor..]) else {
                break;
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROFILE_EXTRACT_SKIPPED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["provider"], "quota_mock");
                assert!(
                    v["retry_after_secs"].is_null(),
                    "expected null, got {}",
                    v["retry_after_secs"]
                );
                assert_eq!(v["trigger_event_id"], 10);
                found_skip = true;
                break;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert!(
            found_skip,
            "0xB9 PROFILE_EXTRACT_SKIPPED frame must be in the WAL"
        );
    }

    #[tokio::test]
    async fn pipeline_caps_oversized_retry_after_at_max_backoff() {
        // Adversarial server sends `Retry-After: 99999999` (~3 years). The
        // tracker's `record_429` enforces MAX_BACKOFF (24h = 86400s); the
        // emit site MUST apply the same cap so the durable WAL value
        // does not diverge from what the in-process tracker actually
        // honours. Without the cap, downstream schedulers reading the
        // WAL frame would plan years-long backoffs while the tracker
        // recovers in a day.
        let (_dir, mut conn, writer, join) = setup().await;
        let ts_ns = 1_778_803_200 * 1_000_000_000;
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, "I live in Berlin", ts_ns);
        let provider = QuotaErrorMock {
            retry_after_secs: Some(99_999_999),
        };
        let guard = ProfileClaimGuard::new(GuardConfig::default());
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            PipelineConn::Owned(&mut conn),
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None,
            false,
        )
        .await
        .unwrap();
        let cap = crate::providers::quota::MAX_BACKOFF.as_secs();
        match out {
            PipelineRun::Skipped(PipelineSkip::QuotaExceeded {
                retry_after_secs, ..
            }) => assert_eq!(retry_after_secs, Some(cap)),
            other => panic!("expected Skipped(QuotaExceeded), got {other:?}"),
        }
        drop(writer);
        let _ = join.await;
    }
}
