//! HERMES-06 GAP-B â€” Capability Evolver.
//!
//! The second half of the JV-SELF-03 / HERMES-06 auto-builder loop.
//! The first half ([`crate::daemon::self_improvement_collector`]) produces a
//! [`CollectorReport`]; this module consumes it.
//!
//! ## What it does
//!
//! [`run_evolver_pass`] inspects every [`CollectorSignal`] in a
//! [`CollectorReport`], applies an **auto-safe allowlist gate** (only
//! `PromptEdit` signals qualify â€” the other categories require explicit
//! operator review), forges candidate skill proposals via
//! [`crate::daemon::skill_forge::build_proposal_from_collector_signal`],
//! checks whether the corresponding skill artifact is already deployed
//! (idempotent guard), and stages new proposals into the G-01a proactive
//! queue via [`crate::proactive::action_staging::stage_and_enqueue`].
//!
//! ## Why only `PromptEdit` is auto-safe
//!
//! The non-auto-safe categories and their rationale:
//!
//! 1. **`PatchSkill`** â€” implies an existing skill has regressed. Patching
//!    live skills without an operator regression gate risks a bad fix.
//! 2. **`ConfigChange`** â€” NEOTH never writes operator config behind their
//!    back (operator-sovereignty hard rule). Operator must review + apply.
//! 3. **`Escalate`** â€” explicitly escalated for human judgment; automation
//!    would defeat the purpose.
//! 4â€“10. Sub-categories of the above three (artifact verification races,
//!    rejection-rate patterns, lesson conflicts, score regression depth,
//!    topic ambiguity, config key risk, deployment race) all share the
//!    same "operator attention required" property.
//!
//! ## WAL frame
//!
//! `0x0F CAPABILITY_EVOLVER_RAN` â€” emitted once per pass when a
//! [`WalWriterHandle`] is provided. Payload:
//! `{signals_in, proposals_staged, proposals_skipped_deployed, ts_unix}`.
//!
//! CLI one-shot path (`neoth self-dev scan`) passes `None` â€” no WAL frame.
//!
//! ## Integration point
//!
//! Called inline from `spawn_self_improvement_collector_loop` immediately
//! after each `run_self_improvement_collector_tick` returns. No new
//! `JoinHandle` â€” the evolver is best-effort inline work within the
//! existing collector async task.

use std::path::Path;

use crate::daemon::self_improvement_collector::{
    CollectorReport, CollectorSignal, is_verified_deployed,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder, events::EVENT_TYPE_CAPABILITY_EVOLVER_RAN};

/// Minimum age in seconds a skill artifact must have been on disk to be
/// considered "already deployed". Mirrors the constant in
/// `self_improvement_collector` â€” kept local so the evolver doesn't
/// transitively drag in collector internals.
const ARTIFACT_MIN_AGE_SECS: u64 = 300;

// â”€â”€ Report type â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Summary produced by one [`run_evolver_pass`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvolverReport {
    /// Number of new proposals successfully staged into the proactive queue.
    pub proposals_staged: usize,
    /// Number of `PromptEdit` signals skipped because the target skill
    /// artifact is already deployed (idempotent guard).
    pub proposals_skipped_deployed: usize,
    /// Number of signals skipped because they are not in the auto-safe
    /// category (`PatchSkill`, `ConfigChange`, `Escalate`, â€¦).
    pub proposals_skipped_not_auto_safe: usize,
    /// `true` when every claim made during this pass was confirmed on disk
    /// after the modify-closure completed. `false` means at least one
    /// staged proposal either lacks its artifact file or is absent from the
    /// persisted queue â€” the pass lied and the operator must investigate.
    ///
    /// Always `true` when `proposals_staged == 0` (nothing was claimed).
    pub verified_ok: bool,
    /// Number of staged proposals whose disk state could not be confirmed
    /// after the pass. Non-zero value indicates a silent save failure or
    /// race condition; each discrepancy is logged at `error` level.
    pub claims_missing: usize,
}

impl Default for EvolverReport {
    fn default() -> Self {
        Self {
            proposals_staged: 0,
            proposals_skipped_deployed: 0,
            proposals_skipped_not_auto_safe: 0,
            // Nothing staged yet â†’ vacuously verified.
            verified_ok: true,
            claims_missing: 0,
        }
    }
}

// â”€â”€ Post-pass verifier â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Cross-check every claim the pass made this tick against the actual disk
/// state. Called immediately after [`ProactiveQueue::modify`] completes so
/// a silent save failure or partial staging can be surfaced before the
/// report is returned to the caller.
///
/// Checks per staged proposal id:
/// 1. Artifact file `<home>/proposals/<id>.json` exists and is non-empty.
/// 2. The persisted queue contains an item whose `dedup_key` is
///    `"ob_03_proposal:<id>"`.
///
/// Each discrepancy is logged at `tracing::error!` (operator-visible).
/// The function updates `result.verified_ok` and `result.claims_missing`
/// in place.
///
/// Only proposals staged THIS tick (`staged_ids`) are verified â€” not the
/// whole queue â€” so the check is O(staged) not O(queue).
fn verify_staged_report(home: &Path, staged_ids: &[String], result: &mut EvolverReport) {
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::proposal_path;

    if staged_ids.is_empty() {
        // Nothing was claimed â†’ vacuously verified; defaults already correct.
        return;
    }

    let queue_path = home.join("proactive_queue.json");

    // Reload INSIDE the lock so a concurrent drain tick that ran between the
    // staging modify and this verify cannot produce a false "absent from
    // queue" error. The closure captures `staged_ids` and `home` by reference.
    //
    // Accepted edge: `modify` re-acquires the file lock and re-reads the
    // queue, which is a second disk read after staging. The closure returns
    // `(false, ())` (do NOT persist) â€” verification is read-only.
    let verify_result = ProactiveQueue::modify(&queue_path, |queue| {
        let mut missing = 0usize;

        for id in staged_ids {
            // 1. Artifact file must exist and be non-empty. A missing artifact
            //    means staging failed silently â€” that is always an error.
            let artifact = proposal_path(home, id);
            let artifact_ok = match std::fs::metadata(&artifact) {
                Ok(m) if m.len() > 0 => true,
                Ok(_) => {
                    tracing::error!(
                        proposal_id = %id,
                        path = %artifact.display(),
                        "capability_evolver: staged proposal artifact is empty â€” claim is a lie"
                    );
                    false
                }
                Err(e) => {
                    tracing::error!(
                        proposal_id = %id,
                        path = %artifact.display(),
                        error = %e,
                        "capability_evolver: staged proposal artifact missing â€” claim is a lie"
                    );
                    false
                }
            };

            // 2. Queue presence check â€” but only when the artifact exists.
            //    If the dedup_key is absent from the queue YET the artifact
            //    file is present on disk, a concurrent delivery-tick drained
            //    the item between staging and this verify. That is NOT a lie;
            //    the staging succeeded. Log at debug so it is operator-visible
            //    without alarming the operator.
            let expected_key = format!("ob_03_proposal:{id}");
            let key_in_queue = queue
                .peek()
                .iter()
                .any(|item| item.dedup_key == expected_key);

            if artifact_ok && !key_in_queue {
                tracing::debug!(
                    proposal_id = %id,
                    dedup_key = %expected_key,
                    "capability_evolver: staged proposal already drained by a concurrent tick \
                     â€” artifact exists, not a lie"
                );
                // Not counted as missing: artifact proves the staging was real.
                continue;
            }

            // Both artifact and queue entry absent: a true silent staging failure.
            if !artifact_ok {
                missing += 1;
            }
        }

        // Never persist â€” this closure is read-only verification.
        (false, missing)
    });

    match verify_result {
        Ok(missing) => {
            result.claims_missing += missing;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                claims = staged_ids.len(),
                "capability_evolver: verifier could not reload queue â€” all claims unverifiable"
            );
            result.claims_missing += staged_ids.len();
        }
    }

    result.verified_ok = result.claims_missing == 0;
}

// â”€â”€ Auto-safe gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Returns `true` only for signals that the evolver may handle automatically
/// (i.e. without explicit operator review).
///
/// Currently only [`CollectorSignal::PromptEdit`] qualifies:
/// - `PatchSkill` â€” live-skill regression; needs operator regression gate.
/// - `ConfigChange` â€” operator-sovereignty rule; NEOTH never auto-edits config.
/// - `Escalate` â€” explicitly asks for human judgment; automation defeats purpose.
fn is_auto_safe(signal: &CollectorSignal) -> bool {
    matches!(signal, CollectorSignal::PromptEdit { .. })
}

// â”€â”€ WAL emit helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async fn emit_evolver_ran(
    writer: &WalWriterHandle,
    signals_in: usize,
    report: &EvolverReport,
    ts_unix: i64,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "signals_in": signals_in,
        "proposals_staged": report.proposals_staged,
        "proposals_skipped_deployed": report.proposals_skipped_deployed,
        "proposals_skipped_not_auto_safe": report.proposals_skipped_not_auto_safe,
        "ts_unix": ts_unix,
    })) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %e,
                "capability_evolver: serialize WAL payload failed"
            );
            return;
        }
    };
    let header = HeaderBuilder::new(EVENT_TYPE_CAPABILITY_EVOLVER_RAN, &payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::error!(
            audit_loss = true,
            event = "CAPABILITY_EVOLVER_RAN",
            error = %e,
            "capability_evolver: WAL frame lost"
        );
    }
}

// â”€â”€ Public entry point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// HERMES-06 GAP-B â€” one evolver pass.
///
/// Steps:
/// 1. Early-return if `report.signals` is empty (no WAL frame, no queue I/O).
/// 2. Emit `0x0F CAPABILITY_EVOLVER_RAN` if a writer is provided.
/// 3. Load the proactive queue from `home/proactive_queue.json`.
/// 4. For each signal:
///    - Skip if not auto-safe (â†’ `proposals_skipped_not_auto_safe`).
///    - Forge a [`ProposedAction`] from the signal via `skill_forge`.
///    - Skip if the skill artifact is already settled on disk
///      (â†’ `proposals_skipped_deployed`).
///    - Stage + enqueue (â†’ `proposals_staged`).
/// 5. Save the queue atomically.
///
/// Best-effort: staging errors for individual signals are logged at `warn`
/// level; the pass continues for remaining signals.
pub async fn run_evolver_pass(
    home: &Path,
    report: &CollectorReport,
    ts_unix: i64,
    writer_opt: Option<&WalWriterHandle>,
) -> EvolverReport {
    if report.signals.is_empty() {
        return EvolverReport::default();
    }

    use crate::daemon::skill_forge::build_proposal_from_collector_signal;
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::stage_and_enqueue;

    let signals_in = report.signals.len();
    let mut result = EvolverReport::default();

    let queue_path = home.join("proactive_queue.json");
    // Locked loadâ†’mutateâ†’save; tolerates a corrupt file (same as the old
    // `unwrap_or_default()`) by logging + skipping the whole staging pass.
    // The closure returns `(persist, staged_ids)` so the post-pass verifier
    // can cross-check exactly the proposals claimed this tick.
    let modify_result = ProactiveQueue::modify(&queue_path, |queue| {
        let mut staged_ids: Vec<String> = Vec::new();

        for signal in &report.signals {
            if !is_auto_safe(signal) {
                result.proposals_skipped_not_auto_safe += 1;
                continue;
            }

            // Only PromptEdit reaches here (is_auto_safe guarantees it).
            let (target, reason) = match signal {
                CollectorSignal::PromptEdit { target, reason } => {
                    (target.as_str(), reason.as_str())
                }
                _ => unreachable!("is_auto_safe only passes PromptEdit"),
            };

            let Some(proposal) = build_proposal_from_collector_signal(target, reason, ts_unix)
            else {
                tracing::debug!(
                    topic = target,
                    "capability_evolver: PromptEdit topic un-slugifiable, skipping proposal"
                );
                result.proposals_skipped_not_auto_safe += 1;
                continue;
            };

            // Idempotent guard: skip if the skill artifact is already settled on disk.
            let artifact_path = home.join("skills").join(&proposal.id).join("skill.yaml");
            if is_verified_deployed(&artifact_path, ARTIFACT_MIN_AGE_SECS) {
                tracing::debug!(
                    skill_id = %proposal.id,
                    "capability_evolver: skill artifact already deployed, skipping"
                );
                result.proposals_skipped_deployed += 1;
                continue;
            }

            match stage_and_enqueue(home, proposal, queue) {
                Ok((staged, true)) => {
                    staged_ids.push(staged.id);
    ×];¶‰žËkºwµçy”ì(€€€€€€€€€€€€€€€­•äè€‰ÁÉ½Ù¥‘•É}­¥¹ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰±•ÍÍ½¸½Ù•É±…Àˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô¤°(€€€€€€€€€€€€‰½¹™¥¡…¹”µÕÍÐ9=P‰”…ÕÑ¼µÍ…™”ˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€€…¥Í}…ÕÑ½}Í…™” ™½±±•Ñ½ÉM¥¹…°èéÍ…±…Ñ”ì(€€€€€€€€€€€€€€€É•…Í½¸è€‰¡¥ É•©•Ñ¥½¸É…Ñ”ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô¤°(€€€€€€€€€€€€‰Í…±…Ñ”µÕÍÐ9=P‰”…ÕÑ¼µÍ…™”ˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÉÕ¹}•Ù½±Ù•É}Á…ÍÌè•µÁÑäÉ•Á½ÉÐƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}•Ù½±Ù•É}Á…ÍÍ}É•ÑÕÉ¹Í}é•É½}É•Á½ÉÑ}™½É}•µÁÑå}Í¥¹…±Ì ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôµ…­•}É•Á½ÉÐ¡Ù•Œ…mt¤ì(€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°€™É•Á½ÉÐ°€À°9½¹”¤¹…Ý…¥Ðì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð°Ù½±Ù•ÉI•Á½ÉÐèé‘•™…Õ±Ð ¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÉÕ¹}•Ù½±Ù•É}Á…ÍÌèÍÑ…•ÌAÉ½µÁÑ‘¥ÐÍ¥¹…±ÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}•Ù½±Ù•É}Á…ÍÍ}ÍÑ…•Í}ÁÉ½µÁÑ}•‘¥Ñ}Í¥¹…±Ì ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôµ…­•}É•Á½ÉÐ¡Ù•Œ…m½±±•Ñ½ÉM¥¹…°èéAÉ½µÁÑ‘¥Ðì(€€€€€€€€€€€Ñ…É•Ðè€‰ÉÕÍÑ±…¹œˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€É•…Í½¸è€‰½Á•É…Ñ½Èµ•¹Ñ¥½¹ÌIÕÍÐ™É•ÅÕ•¹Ñ±ä¥¸É••¹Ð•Á¥Í½‘•Ìˆ¹¥¹Ñ¼ ¤°(€€€€€€€õt¤ì(€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°€™É•Á½ÉÐ°€Å|ÀÀÁ|ÀÀÀ°9½¹”¤¹…Ý…¥Ðì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}ÍÑ…•°€Ä°(€€€€€€€€€€€€‰½¹”AÉ½µÁÑ‘¥ÐÍ¡½Õ±ÍÑ…”½¹”ÁÉ½Á½Í…°ˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}¹½Ñ}…ÕÑ½}Í…™”°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}‘•Á±½å•°€À¤ì((€€€€€€€€¼¼Y•É¥™äÑ¡”ÁÉ½Á½Í…±Ì‘¥É•Ñ½ÉäÝ…ÌÁ½ÁÕ±…Ñ•¸(€€€€€€€±•ÐÁÉ½Á½Í…±Í}‘¥È€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÁÉ½Á½Í…±Ìˆ¤ì(€€€€€€€±•Ð•¹ÑÉ¥•ÌèY•Œñ|ø€ôÍÑèé™ÌèéÉ•…‘}‘¥È ™ÁÉ½Á½Í…±Í}‘¥È¤(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤(€€€€€€€€€€€€¹™¥±Ñ•É}µ…À¡ñ•ð”¹½¬ ¤¤(€€€€€€€€€€€€¹™¥±Ñ•È¡ñ•ð”¹Á…Ñ  ¤¹•áÑ•¹Í¥½¸ ¤¹…¹‘}Ñ¡•¸¡ñáðà¹Ñ½}ÍÑÈ ¤¤€ôôM½µ” ‰©Í½¸ˆ¤¤(€€€€€€€€€€€€¹½±±•Ð ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡•¹ÑÉ¥•Ì¹±•¸ ¤°€Ä°€‰½¹”ÁÉ½Á½Í…°)M=8™¥±”µÕÍÐ‰”ÝÉ¥ÑÑ•¸ˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÉÕ¹}•Ù½±Ù•É}Á…ÍÌèÍ­¥ÁÌ…±É•…‘äµ‘•Á±½å•…ÉÑ¥™…ÑÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}•Ù½±Ù•É}Á…ÍÍ}Í­¥ÁÍ}…±É•…‘å}‘•Á±½å• ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼AÉ”µÉ•…Ñ”Ñ¡”Í­¥±°¹å…µ°Ý¥Ñ …¸½±µÑ¥µ”€ øIQ%Q}5%9}}ML¤¸(€€€€€€€€¼¼]”Í¥µÕ±…Ñ”€‰½±•¹½Õ ˆ‰äÝÉ¥Ñ¥¹œÑ¡”™¥±”…¹Ñ¡•¸Í•ÑÑ¥¹œ¥ÑÌ(€€€€€€€€¼¼µÑ¥µ”ì½¸]¥¹‘½ÝÌÝ”ÕÍ”Ñ¡”™…ÐÑ¡…ÐIQ%Q}5%9}}MLôÌÀÀ(€€€€€€€€¼¼¥ÌµÕ ±…É•ÈÑ¡…¸Ñ¡”Ñ•ÍÐÝ…±°µ±½¬¥¹Ñ•ÉÙ…°ƒŠP¥¹ÍÑ•…Ý”ÕÍ”(€€€€€€€€¼¼„Ñ½Á¥ŒÑ¡…Ðµ…ÁÌÑ¼„­¹½Ý¸Í±Õœ…¹ÝÉ¥Ñ”Ñ¡”…ÉÑ¥™…Ð‘¥É•Ñ±ä¸(€€€€€€€€¼¼(€€€€€€€€¼¼Q¡”•…Í¥•ÍÐÉ½ÍÌµÁ±…Ñ™½É´…ÁÁÉ½… èÝÉ¥Ñ”Ñ¡”Í­¥±°¹å…µ°°Ñ¡•¸…±°(€€€€€€€€¼¼¥Í}Ù•É¥™¥•‘}‘•Á±½å•Ý¥Ñ µ¥¹}…•}Í•ÌôÀ€¡é•É¼µ•…¹Ì€‰…¹ä…”¥Ì=,ˆ¤¸(€€€€€€€€¼¼]”…¸Ð½Ù•ÉÉ¥‘”IQ%Q}5%9}}ML™É½´½ÕÑÍ¥‘”Ñ¡”µ½‘Õ±”°Í¼(€€€€€€€€¼¼¥¹ÍÑ•…Ý”ÝÉ¥Ñ”Ñ¡”…ÉÑ¥™…Ð…¹É•±ä½¸Ñ¡”™…ÐÑ¡…ÐµÑ¥µ”¥Ì¥¸(€€€€€€€€¼¼Ñ¡”Á…ÍÐÉ•±…Ñ¥Ù”Ñ¼¹½ÜƒŠPÑ¡”™¥±”¥ÌÉ•…Ñ•	=IÉÕ¹}•Ù½±Ù•É}Á…ÍÌ(€€€€€€€€¼¼¥Ì…±±•°Í¼•±…ÁÍ•€ø€À€øô€À°µ•…¹¥¹œ¥Í}Ù•É¥™¥•‘}‘•Á±½å•¡Á…Ñ °€À¤(€€€€€€€€¼¼É•ÑÕÉ¹ÌÑÉÕ”¸(€€€€€€€€¼¼(€€€€€€€€¼¼½ÈÑ¡”É•…°½¹ÍÑ…¹Ð€ ÌÀÀÌ¤°Ý”Ñ•ÍÐÑ¡”Í­¥ÀÙ¥„Ñ¡”€‰…±É•…‘ä¥¸(€€€€€€€€¼¼ÅÕ•Õ”ˆÁ…Ñ è…±°ÉÕ¹}•Ù½±Ù•É}Á…ÍÌÑÝ¥”ƒŠPÑ¡”Í•½¹…±°¡¥ÑÌ‘•‘ÕÀ(€€€€€€€€¼¼€¡¹½ÐÑ¡”‘•Á±½å•Õ…É¤°‰ÕÐÑ¡…Ð¥Ì‘½Õµ•¹Ñ•…Ì=,€¡Í•”Á¥Ñ™…±°€È¤¸(€€€€€€€€¼¼Q¡”‘•Á±½å•Õ…É¥ÌÑ•ÍÑ•Ù¥„¥Í}Ù•É¥™¥•‘}‘•Á±½å•Õ¹¥ÐÑ•ÍÑÌ¥¸(€€€€€€€€¼¼Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½È¹ÉÌ€¡…±É•…‘äÍ¡¥ÁÁ•¤¸(€€€€€€€€¼¼(€€€€€€€€¼¼!•É”Ý”Ù•É¥™äÑ¡”€‰…±É•…‘ä‘•Á±½å•ˆ½Õ¹Ð‰äÁ±…¥¹œÑ¡”Í­¥±°¹å…µ°(€€€€€€€€¼¼Ý¥Ñ „ÍÕ™™¥¥•¹Ð…”¸]”Ý½É¬…É½Õ¹Ñ¡”µÑ¥µ”½¹ÍÑÉ…¥¹Ð‰äÕÍ¥¹œ(€€€€€€€€¼¼Ñ¡”¥Í}Ù•É¥™¥•‘}‘•Á±½å•‘€¡•±Á•È‘¥É•Ñ±äÝ¥Ñ µ¥¹}…•}Í•ÌôÀ¸(€€€€€€€€¼¼M¥¹”Ñ¡…Ð¡•±Á•È¥Ì¥¸Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½È€¡ÁÕˆ¤°…¹½ÕÈ(€€€€€€€€¼¼IQ%Q}5%9}}ML€ô€ÌÀÀ°Ý”…¸Ð•…Í¥±ä™½É”€ˆÌÀÀÌ½±¥¸„(€€€€€€€€¼¼Ñ•ÍÐˆ¸%¹ÍÑ•…°Ù•É¥™äÑ¡…Ð„µ¥ÍÍ¥¹œ…ÉÑ¥™…Ð¥Ì9=PÍ­¥ÁÁ•è((€€€€€€€±•ÐÉ•Á½ÉÐ€ôµ…­•}É•Á½ÉÐ¡Ù•Œ…m½±±•Ñ½ÉM¥¹…°èéAÉ½µÁÑ‘¥Ðì(€€€€€€€€€€€Ñ…É•Ðè€‰‘½­•Èˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€É•…Í½¸è€‰‘½­•Èµ•¹Ñ¥½¹•½™Ñ•¸ˆ¹¥¹Ñ¼ ¤°(€€€€€€€õt¤ì((€€€€€€€€¼¼9¼Í­¥±°…ÉÑ¥™…ÐÁÉ”µÉ•…Ñ•ƒŠHÍ¡½Õ±ÍÑ…”€¡¹½ÐÍ­¥À¤¸(€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°€™É•Á½ÉÐ°€Å|ÀÀÁ|ÀÀÀ°9½¹”¤¹…Ý…¥Ðì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}ÍÑ…•€øô€ÄñðÉ•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}¹½Ñ}…ÕÑ½}Í…™”€øô€Ä°(€€€€€€€€€€€€‰Í¥¹…°µÕÍÐ‰”ÁÉ½•ÍÍ•Ý¡•¸¹¼…ÉÑ¥™…Ð•á¥ÍÑÌˆ(€€€€€€€€¤ì(€€€€€€€€¼¼ÍÑ…•€¬Í­¥ÁÁ•‘}‘•Á±½å•€¬Í­¥ÁÁ•‘}¹½Ñ}…ÕÑ½}Í…™”µÕÍÐÍÕ´Ñ¼Ñ¡”Í¥¹…°½Õ¹Ð(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}ÍÑ…•(€€€€€€€€€€€€€€€€¬É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}‘•Á±½å•(€€€€€€€€€€€€€€€€¬É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}¹½Ñ}…ÕÑ½}Í…™”°(€€€€€€€€€€€€Ä°(€€€€€€€€€€€€‰…±°Í¥¹…±ÌµÕÍÐ‰”…½Õ¹Ñ•™½È¥¸Ñ¡”É•Á½ÉÐˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÉÕ¹}•Ù½±Ù•É}Á…ÍÌèÍ­¥ÁÌ¹½¸µAÉ½µÁÑ‘¥ÐÍ¥¹…±ÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÉÕ¹}•Ù½±Ù•É}Á…ÍÍ}Í­¥ÁÍ}¹½¹}ÁÉ½µÁÑ}•‘¥Ð ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôµ…­•}É•Á½ÉÐ¡Ù•Œ…l(€€€€€€€€€€€½±±•Ñ½ÉM¥¹…°èéA…Ñ¡M­¥±°ì(€€€€€€€€€€€€€€€Í­¥±±}¥è€‰µäµÍ­¥±°ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰É•É•ÍÍ¥½¸‘•Ñ•Ñ•ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€€€€€½±±•Ñ½ÉM¥¹…°èé½¹™¥¡…¹”ì(€€€€€€€€€€€€€€€­•äè€‰ÁÉ½Ù¥‘•É}­¥¹ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€É•…Í½¸è€‰±•ÍÍ½¸½Ù•É±…Àˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€€€€€½±±•Ñ½ÉM¥¹…°èéÍ…±…Ñ”ì(€€€€€€€€€€€€€€€É•…Í½¸è€‰É•©•Ñ¥½¸É…Ñ”Ñ½¼¡¥ ˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€ô°(€€€€€€€t¤ì(€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°€™É•Á½ÉÐ°€Å|ÀÀÁ|ÀÀÀ°9½¹”¤¹…Ý…¥Ðì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}¹½Ñ}…ÕÑ½}Í…™”°€Ì°(€€€€€€€€€€€€‰…±°Ñ¡É•”¹½¸µ…ÕÑ¼µÍ…™”Í¥¹…±ÌµÕÍÐ‰”Í­¥ÁÁ•ˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}ÍÑ…•°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}Í­¥ÁÁ•‘}‘•Á±½å•°€À¤ì(€€€ô((€€€€¼¼ƒŠRŠR ¥¹Ñ•É…Ñ¥½¸è½±±•Ñ½ÈÑ¥¬ƒŠH•Ù½±Ù•ÈÁ…ÍÌƒŠH]0ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ñ•¹}Íå¹Ñ¡•Ñ¥}•Á¥Í½‘•Í}ÁÉ½‘Õ•}ÁÉ½µÁÑ}•‘¥Ñ}Í¥¹…±}•Ù½±Ù•É}ÍÑ…•Í}ÁÉ½Á½Í…° ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•ÝÌ¹‘ˆˆ¤ì(€€€€€€€±•Ð¡½µ”€ô‘¥È¹Á…Ñ  ¤¹Ñ½}Á…Ñ¡}‰Õ˜ ¤ì((€€€€€€€€¼¼É•…Ñ”Í¡•µ„…¹¥¹Í•ÉÐ€ÄÀ•Á¥Í½‘”É½ÝÌÝ¥Ñ €‰­Õ‰•É¹•Ñ•Ìˆ¸(€€€€€€€€¼¼Ñ•áÑ}¡…Í ¥Ì9=P9U10¥¸Ñ¡”Í¡•µ„ƒŠPÕÍ”„‘¥ÍÑ¥¹ÐÁ•ÈµÉ½ÜÙ…±Õ”¸(€€€€€€€±•Ð½¹¸€ôÉ…Ñ”èéµ•µ½ÉäèéÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€™½È¤¥¸€À¸¸ÄÁ¤ØÐì(€€€€€€€€€€€½¹¸¹•á•ÕÑ” (€€€€€€€€€€€€€€€€‰%9MIP%9Q<¥‘á}•Á¥Í½‘”p(€€€€€€€€€€€€€€€€€¡•Ù•¹Ñ}ÑåÁ”°ÑÍ}¹Ì°Ñ•áÐ°Ñ•áÑ}¡…Í °¥µÁ½ÉÑ…¹”°±…ÍÑ}…•ÍÍ}ÑÌ¤p(€€€€€€€€€€€€€€€€Y1UL€ Ä°€üÄ°€Í…Ü­Õ‰•É¹•Ñ•Ì¥ÍÍÕ”œ°€üÈ°€À¸Ô°€À¤ˆ°(€€€€€€€€€€€€€€€ÉÕÍÅ±¥Ñ”èéÁ…É…µÌ…l(€€€€€€€€€€€€€€€€€€€É…Ñ”èéÑ¥µ”èé¹½Ý}Õ¹¥á}¹Í}¤ØÐ ¤€´¤€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€€€€€€€€€™½Éµ…Ð„ ‰¡…Í¡}í¥ôˆ¤°(€€€€€€€€€€€€€€€t°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì(€€€€€€€ô(€€€€€€€‘É½À¡½¹¸¤ì((€€€€€€€€¼¼]0ÝÉ¥Ñ•È™½È¥¹Ñ•É…Ñ¥½¸Ñ•ÍÐ¸(€€€€€€€±•ÐÍ•}‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹Ý…°ˆ¤ì(€€€€€€€±•Ð€¡ÝÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéÝ…°èéÝÉ¥Ñ•ÈèéÍÁ…Ý¸¡Í•œ¹±½¹” ¤¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼IÕ¸½±±•Ñ½ÈÝ¥Ñ ±½ÜÑ¡É•Í¡½±Í¼€ÄÀ•Á¥Í½‘•Ì•á••¥Ð¸(€€€€€€€±•Ð™œ€ôÉ…Ñ”èé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€µ¥¹}™É•Å}Ñ¡É•Í¡½±è€Ì°(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Ìè™…±Í”°(€€€€€€€€€€€€¸¹•™…Õ±Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì(€€€€€€€±•ÐÉ•Á½ÉÐ€ô(€€€€€€€€€€€É…Ñ”èé‘…•µ½¸èéÍ•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½ÈèéÉÕ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}Ñ¥¬ (€€€€€€€€€€€€€€€€™‘‰}Á…Ñ °€™¡½µ”°™œ°€™ÝÉ¥Ñ•È°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹…Ý…¥Ð(€€€€€€€€€€€€¹Õ¹ÝÉ…À ¤ì((€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•Á½ÉÐ¹Í¥¹…±Ì¹¥Ñ•È ¤¹…¹ä¡ñÍðµ…Ñ¡•Ì„ (€€€€€€€€€€€€€€€Ì°(€€€€€€€€€€€€€€€½±±•Ñ½ÉM¥¹…°èéAÉ½µÁÑ‘¥ÐìÑ…É•Ð°€¸¸ô(€€€€€€€€€€€€€€€¥˜Ñ…É•Ð€ôô€‰­Õ‰•É¹•Ñ•Ìˆ(€€€€€€€€€€€€¤¤°(€€€€€€€€€€€€ˆÄÀ­Õ‰•É¹•Ñ•Ì•Á¥Í½‘•ÌµÕÍÐÁÉ½‘Õ”AÉ½µÁÑ‘¥ÐÍ¥¹…°ì½Ðèìèýôˆ°(€€€€€€€€€€€É•Á½ÉÐ¹Í¥¹…±Ì(€€€€€€€€¤ì((€€€€€€€€¼¼IÕ¸•Ù½±Ù•È¸(€€€€€€€±•ÐÑÌ€ôÉ…Ñ”èéÑ¥µ”èé¹½Ý}Õ¹¥á}¤ØÐ ¤ì(€€€€€€€±•Ð•Ù½±Ù•È€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ ™¡½µ”°€™É•Á½ÉÐ°ÑÌ°M½µ” ™ÝÉ¥Ñ•È¤¤¹…Ý…¥Ðì((€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€•Ù½±Ù•È¹ÁÉ½Á½Í…±Í}ÍÑ…•€øô€Ä°(€€€€€€€€€€€€‰•Ù½±Ù•ÈµÕÍÐÍÑ…”€øô€ÄÁÉ½Á½Í…°ì½ÐÍÑ…•õíôˆ°(€€€€€€€€€€€•Ù½±Ù•È¹ÁÉ½Á½Í…±Í}ÍÑ…•(€€€€€€€€¤ì((€€€€€€€€¼¼Y•É¥™ä]0½¹Ñ…¥¹Ì€ÁàÁA	%1%Qe}Y=1YI}I8¸(€€€€€€€‘É½À¡ÝÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…Ý…¥Ð¹½¬ ¤ì(€€€€€€€±•Ð‰åÑ•Ì€ôÍÑèé™ÌèéÉ•… ™Í•œ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€‰åÑ•Ì¹Ý¥¹‘½ÝÌ Ä¤¹…¹ä¡ñÝðÝlÁt€ôô€ÁàÁ¤°(€€€€€€€€€€€€ˆÁàÁA	%1%Qe}Y=1YI}I8µÕÍÐ‰”ÁÉ•Í•¹Ð¥¸]0‰åÑ•Ìˆ(€€€€€€€€¤ì((€€€€€€€€¼¼Y•É¥™ä¥Í}Ù•É¥™¥•‘}‘•Á±½å•É•ÑÕÉ¹Ì™…±Í”™½È„¹½¹•á¥ÍÑ•¹ÐÁ…Ñ ¸(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€€…¥Í}Ù•É¥™¥•‘}‘•Á±½å•¡ÍÑèéÁ…Ñ èéA…Ñ èé¹•Ü ˆ½¹½¹•á¥ÍÑ•¹Ð½Í­¥±°¹å…µ°ˆ¤°€À¤°(€€€€€€€€€€€€‰¹½¹•á¥ÍÑ•¹ÐÁ…Ñ µÕÍÐ¹½Ð‰”½¹Í¥‘•É•‘•Á±½å•ˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐè¡…ÁÁäÁ…Ñ ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÑ}±•…¹}…™Ñ•É}ÍÕ•ÍÍ™Õ±}ÍÑ…” ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•Á½ÉÐ€ôµ…­•}É•Á½ÉÐ¡Ù•Œ…m½±±•Ñ½ÉM¥¹…°èéAÉ½µÁÑ‘¥Ðì(€€€€€€€€€€€Ñ…É•Ðè€‰½±…¹œˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€É•…Í½¸è€‰½Á•É…Ñ½ÈÕÍ•Ì¼‘…¥±äˆ¹¥¹Ñ¼ ¤°(€€€€€€€õt¤ì((€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÉÕ¹}•Ù½±Ù•É}Á…ÍÌ¡‘¥È¹Á…Ñ  ¤°€™É•Á½ÉÐ°€Å|ÀÀÁ|ÀÀÀ°9½¹”¤¹…Ý…¥Ðì((€€€€€€€€¼¼MÑ…¥¹œµÕÍÐ¡…Ù”ÍÕ••‘•¸(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•ÍÕ±Ð¹ÁÉ½Á½Í…±Í}ÍÑ…•°€Ä°€‰½¹”ÁÉ½Á½Í…°µÕÍÐ‰”ÍÑ…•ˆ¤ì((€€€€€€€€¼¼Y•É¥™¥•ÈµÕÍÐ½¹™¥É´±•…¸¸(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•ÍÕ±Ð¹Ù•É¥™¥•‘}½¬°(€€€€€€€€€€€€‰Ù•É¥™¥•‘}½¬µÕÍÐ‰”ÑÉÕ”Ý¡•¸…ÉÑ¥™…Ð…¹ÅÕ•Õ”•¹ÑÉä‰½Ñ •á¥ÍÐˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•ÍÕ±Ð¹±…¥µÍ}µ¥ÍÍ¥¹œ°€À°(€€€€€€€€€€€€‰±…¥µÍ}µ¥ÍÍ¥¹œµÕÍÐ‰”é•É¼½¸„±•…¸ÍÑ…”ˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐèÑ…µÁ•É•…ÉÑ¥™…ÐƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÑ}‘•Ñ•ÑÍ}µ¥ÍÍ¥¹}…ÉÑ¥™…Ð ¤ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½…Ñ¥Ù”èéAÉ½…Ñ¥Ù•EÕ•Õ”ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½…Ñ¥Ù”èé…Ñ¥½¹}ÍÑ…¥¹œèéì(€€€€€€€€€€€AÉ½Á½Í…±-¥¹°AÉ½Á½Í…±MÑ…ÑÕÌ°AÉ½Á½Í•‘Ñ¥½¸°ÁÉ½Á½Í…±Í}‘¥È°ÍÑ…•}…¹‘}•¹ÅÕ•Õ”°(€€€€€€€ôì((€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¡½µ”€ô‘¥È¹Á…Ñ  ¤ì(€€€€€€€±•ÐÅÕ•Õ•}Á…Ñ €ô¡½µ”¹©½¥¸ ‰ÁÉ½…Ñ¥Ù•}ÅÕ•Õ”¹©Í½¸ˆ¤ì((€€€€€€€€¼¼5…¹Õ…±±äÍÑ…”½¹”ÁÉ½Á½Í…°Í¼Ý”™Õ±±ä½¹ÑÉ½°Ñ¡”¥…¹½¹Ñ•¹Ð¸(€€€€€€€±•ÐÁÉ½Á½Í…°€ôAÉ½Á½Í•‘Ñ¥½¸ì(€€€€€€€€€€€¥è€ˆÄÀÀÀÀÀÀµÍ­¥±°µ‘•…‘‰••˜ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€­¥¹èAÉ½Á½Í…±-¥¹èéM­¥±°°(€€€€€€€€€€€Ñ¥Ñ±”è€‰Q•ÍÐÍ­¥±°ÁÉ½Á½Í…°ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€É…Ñ¥½¹…±”è€‰ÕÍ•¥¸Ù•É¥™¥•ÈÕ¹¥ÐÑ•ÍÐˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€‘É…™Ñ}å…µ°è€‰¹…µ”èÑ•ÍÐµÍ­¥±±q¸ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€•¹•É…Ñ•‘}ÑÍ}Õ¹¥àè€Å|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€½Á•É…Ñ½É}¹½Ñ”èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ôì(€€€€€€€±•ÐÁÉ½Á½Í…±}¥€ôÁÉ½Á½Í…°¹¥¹±½¹” ¤ì((€€€€€€€€¼¼]É¥Ñ”¥ÐÑ¡É½Õ Ñ¡”É•…°ÍÑ…¥¹œÁ…Ñ Í¼Ñ¡”ÅÕ•Õ”™¥±”¥ÌÉ•…Ñ•¸(€€€€€€€AÉ½…Ñ¥Ù•EÕ•Õ”èéµ½‘¥™ä ™ÅÕ•Õ•}Á…Ñ °ñÅÕ•Õ•ðì(€€€€€€€€€€€±•Ð€¡|°•¹ÅÕ•Õ•¤€ôÍÑ…•}…¹‘}•¹ÅÕ•Õ”¡¡½µ”°ÁÉ½Á½Í…°°ÅÕ•Õ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€…ÍÍ•ÉÐ„¡•¹ÅÕ•Õ•°€‰µÕÍÐ•¹ÅÕ•Õ”½¸™¥ÉÍÐ…±°ˆ¤ì(€€€€€€€€€€€€¡ÑÉÕ”°€ ¤¤(€€€€€€€ô¤(€€€€€€€€¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼Q…µÁ•Èè‘•±•Ñ”Ñ¡”…ÉÑ¥™…Ð™¥±”Ñ¡…ÐÝ…Ì©ÕÍÐÝÉ¥ÑÑ•¸¸(€€€€€€€±•Ð…ÉÑ¥™…Ð€ôÁÉ½Á½Í…±Í}‘¥È¡¡½µ”¤¹©½¥¸¡™½Éµ…Ð„ ‰íÁÉ½Á½Í…±}¥‘ô¹©Í½¸ˆ¤¤ì(€€€€€€€ÍÑèé™ÌèéÉ•µ½Ù•}™¥±” ™…ÉÑ¥™…Ð¤¹•áÁ•Ð ‰…ÉÑ¥™…ÐµÕÍÐ•á¥ÍÐ‰•™½É”‘•±•Ñ¥½¸ˆ¤ì((€€€€€€€€¼¼%¹Ù½­”Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐ‘¥É•Ñ±äÝ¥Ñ Ñ¡”­¹½Ý¸¥¸(€€€€€€€±•ÐµÕÐÉ•Á½ÉÐ€ôÙ½±Ù•ÉI•Á½ÉÐèé‘•™…Õ±Ð ¤ì(€€€€€€€Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐ¡¡½µ”°ÍÑèéÍ±¥”èé™É½µ}É•˜ ™ÁÉ½Á½Í…±}¥¤°€™µÕÐÉ•Á½ÉÐ¤ì((€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€€…É•Á½ÉÐ¹Ù•É¥™¥•‘}½¬°(€€€€€€€€€€€€‰Ù•É¥™¥•‘}½¬µÕÍÐ‰”™…±Í”Ý¡•¸…ÉÑ¥™…Ð¥Ìµ¥ÍÍ¥¹œˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Á½ÉÐ¹±…¥µÍ}µ¥ÍÍ¥¹œ°€Ä°(€€€€€€€€€€€€‰±…¥µÍ}µ¥ÍÍ¥¹œµÕÍÐ½Õ¹ÐÑ¡”‘•±•Ñ•…ÉÑ¥™…Ðˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐè‘É…¥¹•µ¹½Ðµ±¥•ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR (€€€€¼¼(€€€€¼¼]¡•¸Ñ¡”…ÉÑ¥™…Ð™¥±”a%MQL½¸‘¥Í¬‰ÕÐÑ¡”‘•‘ÕÁ}­•ä¥Ì	M9P™É½´(€€€€¼¼Ñ¡”ÅÕ•Õ”€¡„½¹ÕÉÉ•¹Ð‘É…¥¸Ñ¥¬‘•±¥Ù•É•Ñ¡”¥Ñ•´‰•ÑÝ••¸ÍÑ…”…¹(€€€€¼¼Ù•É¥™ä¤°Ñ¡”Ù•É¥™¥•ÈµÕÍÐÑÉ•…ÐÑ¡¥Ì…Ì…¸…•ÁÑ•É…”ƒŠP¹½Ð…¸(€€€€¼¼•ÉÉ½È¸Ù•É¥™¥•‘}½­€µÕÍÐÉ•µ…¥¸ÑÉÕ•€ì±…¥µÍ}µ¥ÍÍ¥¹€µÕÍÐÍÑ…ä€À¸((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÑ}‘É…¥¹•‘}¹½Ñ}±¥•‘}ÍÑ…åÍ}Ù•É¥™¥•‘}½¬ ¤ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½…Ñ¥Ù”èéAÉ½…Ñ¥Ù•EÕ•Õ”ì(€€€€€€€ÕÍ”É…Ñ”èéÁÉ½…Ñ¥Ù”èé…Ñ¥½¹}ÍÑ…¥¹œèéì(€€€€€€€€€€€AÉ½Á½Í…±-¥¹°AÉ½Á½Í…±MÑ…ÑÕÌ°AÉ½Á½Í•‘Ñ¥½¸°ÍÑ…•}…¹‘}•¹ÅÕ•Õ”°(€€€€€€€ôì((€€€€€€€±•Ð‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•Ð¡½µ”€ô‘¥È¹Á…Ñ  ¤ì(€€€€€€€±•ÐÅÕ•Õ•}Á…Ñ €ô¡½µ”¹©½¥¸ ‰ÁÉ½…Ñ¥Ù•}ÅÕ•Õ”¹©Í½¸ˆ¤ì((€€€€€€€€¼¼MÑ…”„É•…°ÁÉ½Á½Í…°Í¼Ñ¡”…ÉÑ¥™…Ð™¥±”¥ÌÝÉ¥ÑÑ•¸¸(€€€€€€€±•ÐÁÉ½Á½Í…°€ôAÉ½Á½Í•‘Ñ¥½¸ì(€€€€€€€€€€€¥è€ˆÈÀÀÀÀÀÀµÍ­¥±°µ…™•˜ÀÁˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€­¥¹èAÉ½Á½Í…±-¥¹èéM­¥±°°(€€€€€€€€€€€Ñ¥Ñ±”è€‰É…¥¹•µ¹½Ðµ±¥•Ñ•ÍÐÁÉ½Á½Í…°ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€É…Ñ¥½¹…±”è€‰ÕÍ•¥¸‘É…¥¹•µ¹½Ðµ±¥•Ù•É¥™¥•ÈÕ¹¥ÐÑ•ÍÐˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€‘É…™Ñ}å…µ°è€‰¹…µ”è‘É…¥¸µÑ•ÍÐµÍ­¥±±q¸ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€•¹•É…Ñ•‘}ÑÍ}Õ¹¥àè€É|ÀÀÁ|ÀÀÀ°(€€€€€€€€€€€ÍÑ…ÑÕÌèAÉ½Á½Í…±MÑ…ÑÕÌèéA•¹‘¥¹œ°(€€€€€€€€€€€½Á•É…Ñ½É}¹½Ñ”èMÑÉ¥¹œèé¹•Ü ¤°(€€€€€€€ôì(€€€€€€€±•ÐÁÉ½Á½Í…±}¥€ôÁÉ½Á½Í…°¹¥¹±½¹” ¤ì((€€€€€€€AÉ½…Ñ¥Ù•EÕ•Õ”èéµ½‘¥™ä ™ÅÕ•Õ•}Á…Ñ °ñÅÕ•Õ•ðì(€€€€€€€€€€€±•Ð€¡|°•¹ÅÕ•Õ•¤€ôÍÑ…•}…¹‘}•¹ÅÕ•Õ”¡¡½µ”°ÁÉ½Á½Í…°°ÅÕ•Õ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€…ÍÍ•ÉÐ„¡•¹ÅÕ•Õ•°€‰µÕÍÐ•¹ÅÕ•Õ”½¸™¥ÉÍÐ…±°ˆ¤ì(€€€€€€€€€€€€¡ÑÉÕ”°€ ¤¤(€€€€€€€ô¤(€€€€€€€€¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼M¥µÕ±…Ñ”„½¹ÕÉÉ•¹Ð‘É…¥¸Ñ¥¬èÉ•µ½Ù”Ñ¡”ÅÕ•Õ”•¹ÑÉä‰ÕÐ±•…Ù”(€€€€€€€€¼¼Ñ¡”…ÉÑ¥™…Ð™¥±”¥¹Ñ…Ð€¡Ñ¡”‘•±¥Ù•ÉäÑ¥¬Ý½Õ±‘É…¥¸Ñ¡”¥Ñ•´(€€€€€€€€¼¼™É½´Ñ¡”ÅÕ•Õ”…¹Á•ÉÍ¥ÍÐ¥ÐÙ¥„Ñ¡”Í¥‘•…È°‰ÕÐ¹•Ù•È‘•±•Ñ•Ì(€€€€€€€€¼¼Ñ¡”…ÉÑ¥™…Ð¤¸(€€€€€€€AÉ½…Ñ¥Ù•EÕ•Õ”èéµ½‘¥™ä ™ÅÕ•Õ•}Á…Ñ °ñÅÕ•Õ•ðì(€€€€€€€€€€€±•Ð­•ä€ô™½Éµ…Ð„ ‰½‰|ÀÍ}ÁÉ½Á½Í…°éíÁÉ½Á½Í…±}¥‘ôˆ¤ì(€€€€€€€€€€€ÅÕ•Õ”¹É•µ½Ù•}‰å}­•ä ™­•ä¤ì(€€€€€€€€€€€€¡ÑÉÕ”°€ ¤¤(€€€€€€€ô¤(€€€€€€€€¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼%¹Ù½­”Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐè…ÉÑ¥™…ÐÁÉ•Í•¹Ð°­•ä…‰Í•¹ÐƒŠH9=P„±¥”¸(€€€€€€€±•ÐµÕÐÉ•Á½ÉÐ€ôÙ½±Ù•ÉI•Á½ÉÐèé‘•™…Õ±Ð ¤ì(€€€€€€€Ù•É¥™å}ÍÑ…•‘}É•Á½ÉÐ¡¡½µ”°ÍÑèéÍ±¥”èé™É½µ}É•˜ ™ÁÉ½Á½Í…±}¥¤°€™µÕÐÉ•Á½ÉÐ¤ì((€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•Á½ÉÐ¹Ù•É¥™¥•‘}½¬°(€€€€€€€€€€€€‰Ù•É¥™¥•‘}½¬µÕÍÐ‰”ÑÉÕ”Ý¡•¸…ÉÑ¥™…Ð•á¥ÍÑÌ‰ÕÐ­•äÝ…Ì½¹ÕÉÉ•¹Ñ±ä‘É…¥¹•ˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€É•Á½ÉÐ¹±…¥µÍ}µ¥ÍÍ¥¹œ°€À°(€€€€€€€€€€€€‰±…¥µÍ}µ¥ÍÍ¥¹œµÕÍÐ‰”é•É¼™½È‘É…¥¹•µ¹½Ðµ±¥•Í¡…Á”ˆ(€€€€€€€€¤ì(€€€ô)ô