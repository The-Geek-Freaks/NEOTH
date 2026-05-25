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

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::profile::apply::{ApplyOutcome, apply_delta, record_blocked};
use crate::profile::claim_guard::{GuardOutcome, GuardReason, ProfileClaimGuard};
use crate::profile::delta::ProfileDelta;
use crate::profile::extension_registry::TypedExtensionRegistry;
use crate::profile::extract::extract as extract_delta;
use crate::profile::redaction;
use crate::profile::timestamp_check::TimestampPolicy;
use crate::profile::validate::{DroppedClaim, validate};
use crate::profile::window_attribute::attribute_segments;
use crate::profile::window_extract::extract_window;
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

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
pub async fn run_pipeline(
    conn: &mut Connection,
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

    // Stage 1 — window_extract.
    let window = extract_window(conn, trigger_event_id, turns_back)
        .context("pipeline stage 1: window_extract")?;

    // Stage 2 — window_attribute.
    let attributed = attribute_segments(&window);
    if !attributed.has_user_speech_segments() {
        return Ok(PipelineRun::Skipped(PipelineSkip::NoUserSpeechInWindow));
    }

    // Stage 3 — extract (LLM call). Short-circuits if no eligible
    // segments survive attribution.
    let delta: ProfileDelta = extract_delta(provider, &attributed)
        .await
        .context("pipeline stage 3: profile.extract")?;

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
    let redactions = load_active_redactions(conn)?;
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
        use crate::profile::approval_gate::{approval_gate, ApprovalOutcome};
        let outcome = approval_gate(
            &guarded,
            ctx.config,
            ctx.autonomy,
            ctx.is_tty,
            conn,
            ctx.confirm_fn,
            now_unix,
        )
        .context("pipeline stage 5b: approval_gate")?;
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

    // Stage 6 — apply. Idempotent on extraction_id.
    let apply_outcome = apply_delta(conn, writer, &guarded, now_unix as i64)
        .await
        .context("pipeline stage 6: profile.apply")?;

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
/// the data stays on-device — no privacy concern under H3.
fn is_local_inference_provider(name: &str) -> bool {
    matches!(name, "local_qwen" | "hermes" | "openclaw")
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

// Use `redaction::lookup_active` for single-field lookups in tooling
// paths. The pipeline batch-loads via the dedicated query above so
// each turn pays one round-trip, not N.
#[allow(dead_code)]
fn ensure_redaction_module_used(conn: &Connection) -> Result<()> {
    let _ = redaction::lookup_active(conn, "identity.x")?;
    Ok(())
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
            &mut conn,
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None, // ADV-03 Phase 5: gate context unused in this test
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
            &mut conn,
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            100,
            None, // ADV-03 Phase 5: gate context unused in this test
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
        redaction::add(&conn, "identity.location", true, None, "operator", 1).unwrap();

        let provider = LlmMock {
            reply: valid_llm_reply_with_today_date(),
        };
        let guard = ProfileClaimGuard::default();
        let extensions = TypedExtensionRegistry::default();
        let out = run_pipeline(
            &mut conn,
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None, // ADV-03 Phase 5: gate context unused in this test
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
            &mut conn,
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None, // ADV-03 Phase 5: gate context unused in this test
        )
        .await
        .unwrap();
        let out2 = run_pipeline(
            &mut conn,
            &writer,
            &provider,
            10,
            2,
            &guard,
            &extensions,
            1_778_803_200,
            None, // ADV-03 Phase 5: gate context unused in this test
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
        for name in ["local_qwen", "hermes", "openclaw"] {
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
        assert!(is_local_inference_provider("hermes"));
        assert!(is_local_inference_provider("openclaw"));
        assert!(!is_local_inference_provider("claude_cli"));
        assert!(!is_local_inference_provider("openai_api"));
        assert!(!is_local_inference_provider("gemini_api"));
        assert!(!is_local_inference_provider("aws_bedrock"));
        assert!(!is_local_inference_provider("azure_openai"));
    }
}
