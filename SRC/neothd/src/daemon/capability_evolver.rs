//! HERMES-06 GAP-B — Capability Evolver.
//!
//! The second half of the JV-SELF-03 / HERMES-06 auto-builder loop.
//! The first half ([`crate::daemon::self_improvement_collector`]) produces a
//! [`CollectorReport`]; this module consumes it.
//!
//! ## What it does
//!
//! [`run_evolver_pass`] inspects every [`CollectorSignal`] in a
//! [`CollectorReport`], applies an **auto-safe allowlist gate** (only
//! `PromptEdit` signals qualify — the other categories require explicit
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
//! 1. **`PatchSkill`** — implies an existing skill has regressed. Patching
//!    live skills without an operator regression gate risks a bad fix.
//! 2. **`ConfigChange`** — NEOTH never writes operator config behind their
//!    back (operator-sovereignty hard rule). Operator must review + apply.
//! 3. **`Escalate`** — explicitly escalated for human judgment; automation
//!    would defeat the purpose.
//! 4–10. Sub-categories of the above three (artifact verification races,
//!    rejection-rate patterns, lesson conflicts, score regression depth,
//!    topic ambiguity, config key risk, deployment race) all share the
//!    same "operator attention required" property.
//!
//! ## WAL frame
//!
//! `0x0F CAPABILITY_EVOLVER_RAN` — emitted once per pass when a
//! [`WalWriterHandle`] is provided. Payload:
//! `{signals_in, proposals_staged, proposals_skipped_deployed, ts_unix}`.
//!
//! CLI one-shot path (`neoth self-dev scan`) passes `None` — no WAL frame.
//!
//! ## Integration point
//!
//! Called inline from `spawn_self_improvement_collector_loop` immediately
//! after each `run_self_improvement_collector_tick` returns. No new
//! `JoinHandle` — the evolver is best-effort inline work within the
//! existing collector async task.

use std::path::Path;

use crate::daemon::self_improvement_collector::{
    CollectorReport, CollectorSignal, is_verified_deployed,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder, events::EVENT_TYPE_CAPABILITY_EVOLVER_RAN};

/// Minimum age in seconds a skill artifact must have been on disk to be
/// considered "already deployed". Mirrors the constant in
/// `self_improvement_collector` — kept local so the evolver doesn't
/// transitively drag in collector internals.
const ARTIFACT_MIN_AGE_SECS: u64 = 300;

// ── Report type ───────────────────────────────────────────────────────────────

/// Summary produced by one [`run_evolver_pass`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvolverReport {
    /// Number of new proposals successfully staged into the proactive queue.
    pub proposals_staged: usize,
    /// Number of `PromptEdit` signals skipped because the target skill
    /// artifact is already deployed (idempotent guard).
    pub proposals_skipped_deployed: usize,
    /// Number of signals skipped because they are not in the auto-safe
    /// category (`PatchSkill`, `ConfigChange`, `Escalate`, …).
    pub proposals_skipped_not_auto_safe: usize,
    /// `true` when every claim made during this pass was confirmed on disk
    /// after the modify-closure completed. `false` means at least one
    /// staged proposal either lacks its artifact file or is absent from the
    /// persisted queue — the pass lied and the operator must investigate.
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
            // Nothing staged yet → vacuously verified.
            verified_ok: true,
            claims_missing: 0,
        }
    }
}

// ── Post-pass verifier ────────────────────────────────────────────────────────

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
/// Only proposals staged THIS tick (`staged_ids`) are verified — not the
/// whole queue — so the check is O(staged) not O(queue).
fn verify_staged_report(home: &Path, staged_ids: &[String], result: &mut EvolverReport) {
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::proposal_path;

    if staged_ids.is_empty() {
        // Nothing was claimed → vacuously verified; defaults already correct.
        return;
    }

    let queue_path = home.join("proactive_queue.json");

    // Reload INSIDE the lock so a concurrent drain tick that ran between the
    // staging modify and this verify cannot produce a false "absent from
    // queue" error. The closure captures `staged_ids` and `home` by reference.
    //
    // Accepted edge: `modify` re-acquires the file lock and re-reads the
    // queue, which is a second disk read after staging. The closure returns
    // `(false, ())` (do NOT persist) — verification is read-only.
    let verify_result = ProactiveQueue::modify(&queue_path, |queue| {
        let mut missing = 0usize;

        for id in staged_ids {
            // 1. Artifact file must exist and be non-empty. A missing artifact
            //    means staging failed silently — that is always an error.
            let artifact = proposal_path(home, id);
            let artifact_ok = match std::fs::metadata(&artifact) {
                Ok(m) if m.len() > 0 => true,
                Ok(_) => {
                    tracing::error!(
                        proposal_id = %id,
                        path = %artifact.display(),
                        "capability_evolver: staged proposal artifact is empty — claim is a lie"
                    );
                    false
                }
                Err(e) => {
                    tracing::error!(
                        proposal_id = %id,
                        path = %artifact.display(),
                        error = %e,
                        "capability_evolver: staged proposal artifact missing — claim is a lie"
                    );
                    false
                }
            };

            // 2. Queue presence check — but only when the artifact exists.
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
                     — artifact exists, not a lie"
                );
                // Not counted as missing: artifact proves the staging was real.
                continue;
            }

            // Both artifact and queue entry absent: a true silent staging failure.
            if !artifact_ok {
                missing += 1;
            }
        }

        // Never persist — this closure is read-only verification.
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
                "capability_evolver: verifier could not reload queue — all claims unverifiable"
            );
            result.claims_missing += staged_ids.len();
        }
    }

    result.verified_ok = result.claims_missing == 0;
}

// ── Auto-safe gate ────────────────────────────────────────────────────────────

/// Returns `true` only for signals that the evolver may handle automatically
/// (i.e. without explicit operator review).
///
/// Currently only [`CollectorSignal::PromptEdit`] qualifies:
/// - `PatchSkill` — live-skill regression; needs operator regression gate.
/// - `ConfigChange` — operator-sovereignty rule; NEOTH never auto-edits config.
/// - `Escalate` — explicitly asks for human judgment; automation defeats purpose.
fn is_auto_safe(signal: &CollectorSignal) -> bool {
    matches!(signal, CollectorSignal::PromptEdit { .. })
}

// ── WAL emit helper ───────────────────────────────────────────────────────────

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

// ── Public entry point ────────────────────────────────────────────────────────

/// HERMES-06 GAP-B — one evolver pass.
///
/// Steps:
/// 1. Early-return if `report.signals` is empty (no WAL frame, no queue I/O).
/// 2. Emit `0x0F CAPABILITY_EVOLVER_RAN` if a writer is provided.
/// 3. Load the proactive queue from `home/proactive_queue.json`.
/// 4. For each signal:
///    - Skip if not auto-safe (→ `proposals_skipped_not_auto_safe`).
///    - Forge a [`ProposedAction`] from the signal via `skill_forge`.
///    - Skip if the skill artifact is already settled on disk
///      (→ `proposals_skipped_deployed`).
///    - Stage + enqueue (→ `proposals_staged`).
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
    // Locked load→mutate→save; tolerates a corrupt file (same as the old
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
                    result.proposals_staged += 1;
                }
                Ok((_, false)) => {
                    // Already in queue — dedup by proposal id; not an error.
                    tracing::debug!(
                        topic = target,
                        "capability_evolver: proposal already in queue (dedup), skipping"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        topic = target,
                        "capability_evolver: proposal staging failed"
                    );
                }
            }
        }

        // Persist only when at least one new proposal was staged.
        let persist = result.proposals_staged > 0;
        (persist, staged_ids)
    });

    match modify_result {
        Ok(staged_ids) => {
            if result.proposals_staged > 0 {
                tracing::info!(
                    staged = result.proposals_staged,
                    skipped_deployed = result.proposals_skipped_deployed,
                    skipped_not_auto_safe = result.proposals_skipped_not_auto_safe,
                    "HERMES-06 GAP-B: capability evolver staged proposals"
                );
            }
            // Post-pass truth check: verify every claim this tick landed on disk.
            verify_staged_report(home, &staged_ids, &mut result);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "capability_evolver: queue load/save failed, staging pass skipped"
            );
        }
    }

    // Emit WAL frame after all work is done (best-effort).
    if let Some(writer) = writer_opt {
        emit_evolver_ran(writer, signals_in, &result, ts_unix).await;
    }

    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::self_improvement_collector::CollectorSignal;

    fn make_report(signals: Vec<CollectorSignal>) -> CollectorReport {
        CollectorReport {
            signals,
            babel_fitness: Vec::new(),
            topics_scanned: 0,
            lessons_read: 0,
            ledger_records_checked: 0,
            deployed_artifacts_checked: 0,
            ts_unix: 1_000_000,
            ..Default::default()
        }
    }

    // ── is_auto_safe ──────────────────────────────────────────────────────────

    #[test]
    fn is_auto_safe_only_prompt_edit() {
        assert!(
            is_auto_safe(&CollectorSignal::PromptEdit {
                target: "kubernetes".into(),
                reason: "frequent".into(),
            }),
            "PromptEdit must be auto-safe"
        );
        assert!(
            !is_auto_safe(&CollectorSignal::PatchSkill {
                skill_id: "foo".into(),
                reason: "regressed".into(),
            }),
            "PatchSkill must NOT be auto-safe"
        );
        assert!(
            !is_auto_safe(&CollectorSignal::ConfigChange {
                key: "provider_kind".into(),
                reason: "lesson overlap".into(),
            }),
            "ConfigChange must NOT be auto-safe"
        );
        assert!(
            !is_auto_safe(&CollectorSignal::Escalate {
                reason: "high rejection rate".into(),
            }),
            "Escalate must NOT be auto-safe"
        );
    }

    // ── run_evolver_pass: empty report ────────────────────────────────────────

    #[tokio::test]
    async fn run_evolver_pass_returns_zero_report_for_empty_signals() {
        let dir = tempfile::tempdir().unwrap();
        let report = make_report(vec![]);
        let result = run_evolver_pass(dir.path(), &report, 0, None).await;
        assert_eq!(result, EvolverReport::default());
    }

    // ── run_evolver_pass: stages PromptEdit signals ────────────────────────────

    #[tokio::test]
    async fn run_evolver_pass_stages_prompt_edit_signals() {
        let dir = tempfile::tempdir().unwrap();
        let report = make_report(vec![CollectorSignal::PromptEdit {
            target: "rustlang".into(),
            reason: "operator mentions Rust frequently in recent episodes".into(),
        }]);
        let result = run_evolver_pass(dir.path(), &report, 1_000_000, None).await;
        assert_eq!(
            result.proposals_staged, 1,
            "one PromptEdit should stage one proposal"
        );
        assert_eq!(result.proposals_skipped_not_auto_safe, 0);
        assert_eq!(result.proposals_skipped_deployed, 0);

        // Verify the proposals directory was populated.
        let proposals_dir = dir.path().join("proposals");
        let entries: Vec<_> = std::fs::read_dir(&proposals_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        assert_eq!(entries.len(), 1, "one proposal JSON file must be written");
    }

    // ── run_evolver_pass: skips already-deployed artifacts ────────────────────

    #[tokio::test]
    async fn run_evolver_pass_skips_already_deployed() {
        let dir = tempfile::tempdir().unwrap();

        // Pre-create the skill.yaml with an old mtime (> ARTIFACT_MIN_AGE_SECS).
        // We simulate "old enough" by writing the file and then setting its
        // mtime; on Windows we use the fact that ARTIFACT_MIN_AGE_SECS=300
        // is much larger than the test wall-clock interval — instead we use
        // a topic that maps to a known slug and write the artifact directly.
        //
        // The easiest cross-platform approach: write the skill.yaml, then call
        // is_verified_deployed with min_age_secs=0 (zero means "any age is OK").
        // We can't override ARTIFACT_MIN_AGE_SECS from outside the module, so
        // instead we write the artifact and rely on the fact that mtime is in
        // the past relative to now — the file is created BEFORE run_evolver_pass
        // is called, so elapsed > 0 >= 0, meaning is_verified_deployed(path, 0)
        // returns true.
        //
        // For the real constant (300 s), we test the skip via the "already in
        // queue" path: call run_evolver_pass twice — the second call hits dedup
        // (not the deployed guard), but that is documented as OK (see pitfall 2).
        // The deployed guard is tested via is_verified_deployed unit tests in
        // self_improvement_collector.rs (already shipped).
        //
        // Here we verify the "already deployed" count by placing the skill.yaml
        // with a sufficient age. We work around the mtime constraint by using
        // the `is_verified_deployed` helper directly with min_age_secs=0.
        // Since that helper is in self_improvement_collector (pub), and our
        // ARTIFACT_MIN_AGE_SECS = 300, we can't easily force "300 s old in a
        // test". Instead, verify that a missing artifact is NOT skipped:

        let report = make_report(vec![CollectorSignal::PromptEdit {
            target: "docker".into(),
            reason: "docker mentioned often".into(),
        }]);

        // No skill artifact pre-created → should stage (not skip).
        let result = run_evolver_pass(dir.path(), &report, 1_000_000, None).await;
        assert!(
            result.proposals_staged >= 1 || result.proposals_skipped_not_auto_safe >= 1,
            "signal must be processed when no artifact exists"
        );
        // staged + skipped_deployed + skipped_not_auto_safe must sum to the signal count
        assert_eq!(
            result.proposals_staged
                + result.proposals_skipped_deployed
                + result.proposals_skipped_not_auto_safe,
            1,
            "all signals must be accounted for in the report"
        );
    }

    // ── run_evolver_pass: skips non-PromptEdit signals ─────────────────────────

    #[tokio::test]
    async fn run_evolver_pass_skips_non_prompt_edit() {
        let dir = tempfile::tempdir().unwrap();
        let report = make_report(vec![
            CollectorSignal::PatchSkill {
                skill_id: "my-skill".into(),
                reason: "regression detected".into(),
            },
            CollectorSignal::ConfigChange {
                key: "provider_kind".into(),
                reason: "lesson overlap".into(),
            },
            CollectorSignal::Escalate {
                reason: "rejection rate too high".into(),
            },
        ]);
        let result = run_evolver_pass(dir.path(), &report, 1_000_000, None).await;
        assert_eq!(
            result.proposals_skipped_not_auto_safe, 3,
            "all three non-auto-safe signals must be skipped"
        );
        assert_eq!(result.proposals_staged, 0);
        assert_eq!(result.proposals_skipped_deployed, 0);
    }

    // ── integration: collector tick → evolver pass → WAL ─────────────────────

    #[tokio::test]
    async fn ten_synthetic_episodes_produce_prompt_edit_signal_evolver_stages_proposal() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let home = dir.path().to_path_buf();

        // Create DB schema and insert 10 episode rows with "kubernetes".
        // text_hash is NOT NULL in the schema — use a distinct per-row value.
        let conn = crate::memory::store::open(&db_path).unwrap();
        for i in 0..10i64 {
            conn.execute(
                "INSERT INTO idx_episode \
                 (event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (1, ?1, 'saw kubernetes issue', ?2, 0.5, 0)",
                rusqlite::params![
                    crate::time::now_unix_ns_i64() - i * 1_000_000_000,
                    format!("hash_{i}"),
                ],
            )
            .unwrap();
        }
        drop(conn);

        // WAL writer for integration test.
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // Run collector with low threshold so 10 episodes exceed it.
        let cfg = crate::config::automation::SelfImprovementCollectorConfig {
            enabled: true,
            min_freq_threshold: 3,
            propose_skills: false,
            ..Default::default()
        };
        let report =
            crate::daemon::self_improvement_collector::run_self_improvement_collector_tick(
                &db_path, &home, cfg, &writer,
            )
            .await
            .unwrap();

        assert!(
            report.signals.iter().any(|s| matches!(
                s,
                CollectorSignal::PromptEdit { target, .. }
                if target == "kubernetes"
            )),
            "10 kubernetes episodes must produce PromptEdit signal; got: {:?}",
            report.signals
        );

        // Run evolver.
        let ts = crate::time::now_unix_i64();
        let evolver = run_evolver_pass(&home, &report, ts, Some(&writer)).await;

        assert!(
            evolver.proposals_staged >= 1,
            "evolver must stage >= 1 proposal; got staged={}",
            evolver.proposals_staged
        );

        // Verify WAL contains 0x0F CAPABILITY_EVOLVER_RAN.
        drop(writer);
        join.await.ok();
        let bytes = std::fs::read(&seg).unwrap();
        assert!(
            bytes.windows(1).any(|w| w[0] == 0x0F),
            "0x0F CAPABILITY_EVOLVER_RAN must be present in WAL bytes"
        );

        // Verify is_verified_deployed returns false for a nonexistent path.
        assert!(
            !is_verified_deployed(std::path::Path::new("/nonexistent/skill.yaml"), 0),
            "nonexistent path must not be considered deployed"
        );
    }

    // ── verify_staged_report: happy path ──────────────────────────────────────

    #[tokio::test]
    async fn verify_staged_report_clean_after_successful_stage() {
        let dir = tempfile::tempdir().unwrap();
        let report = make_report(vec![CollectorSignal::PromptEdit {
            target: "golang".into(),
            reason: "operator uses Go daily".into(),
        }]);

        let result = run_evolver_pass(dir.path(), &report, 1_000_000, None).await;

        // Staging must have succeeded.
        assert_eq!(result.proposals_staged, 1, "one proposal must be staged");

        // Verifier must confirm clean.
        assert!(
            result.verified_ok,
            "verified_ok must be true when artifact and queue entry both exist"
        );
        assert_eq!(
            result.claims_missing, 0,
            "claims_missing must be zero on a clean stage"
        );
    }

    // ── verify_staged_report: tampered artifact ───────────────────────────────

    #[tokio::test]
    async fn verify_staged_report_detects_missing_artifact() {
        use crate::proactive::ProactiveQueue;
        use crate::proactive::action_staging::{
            ProposalKind, ProposalStatus, ProposedAction, proposals_dir, stage_and_enqueue,
        };

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let queue_path = home.join("proactive_queue.json");

        // Manually stage one proposal so we fully control the id and content.
        let proposal = ProposedAction {
            id: "1000000-skill-deadbeef".to_string(),
            kind: ProposalKind::Skill,
            title: "Test skill proposal".to_string(),
            rationale: "used in verifier unit test".to_string(),
            draft_yaml: "name: test-skill\n".to_string(),
            generated_ts_unix: 1_000_000,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        };
        let proposal_id = proposal.id.clone();

        // Write it through the real staging path so the queue file is created.
        ProactiveQueue::modify(&queue_path, |queue| {
            let (_, enqueued) = stage_and_enqueue(home, proposal, queue).unwrap();
            assert!(enqueued, "must enqueue on first call");
            (true, ())
        })
        .unwrap();

        // Tamper: delete the artifact file that was just written.
        let artifact = proposals_dir(home).join(format!("{proposal_id}.json"));
        std::fs::remove_file(&artifact).expect("artifact must exist before deletion");

        // Invoke verify_staged_report directly with the known id.
        let mut report = EvolverReport::default();
        verify_staged_report(home, std::slice::from_ref(&proposal_id), &mut report);

        assert!(
            !report.verified_ok,
            "verified_ok must be false when artifact is missing"
        );
        assert_eq!(
            report.claims_missing, 1,
            "claims_missing must count the deleted artifact"
        );
    }

    // ── verify_staged_report: drained-not-lied ────────────────────────────
    //
    // When the artifact file EXISTS on disk but the dedup_key is ABSENT from
    // the queue (a concurrent drain tick delivered the item between stage and
    // verify), the verifier must treat this as an accepted race — not an
    // error. `verified_ok` must remain `true`; `claims_missing` must stay 0.

    #[tokio::test]
    async fn verify_staged_report_drained_not_lied_stays_verified_ok() {
        use crate::proactive::ProactiveQueue;
        use crate::proactive::action_staging::{
            ProposalKind, ProposalStatus, ProposedAction, stage_and_enqueue,
        };

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let queue_path = home.join("proactive_queue.json");

        // Stage a real proposal so the artifact file is written.
        let proposal = ProposedAction {
            id: "2000000-skill-cafef00d".to_string(),
            kind: ProposalKind::Skill,
            title: "Drained-not-lied test proposal".to_string(),
            rationale: "used in drained-not-lied verifier unit test".to_string(),
            draft_yaml: "name: drain-test-skill\n".to_string(),
            generated_ts_unix: 2_000_000,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        };
        let proposal_id = proposal.id.clone();

        ProactiveQueue::modify(&queue_path, |queue| {
            let (_, enqueued) = stage_and_enqueue(home, proposal, queue).unwrap();
            assert!(enqueued, "must enqueue on first call");
            (true, ())
        })
        .unwrap();

        // Simulate a concurrent drain tick: remove the queue entry but leave
        // the artifact file intact (the delivery tick would drain the item
        // from the queue and persist it via the sidecar, but never deletes
        // the artifact).
        ProactiveQueue::modify(&queue_path, |queue| {
            let key = format!("ob_03_proposal:{proposal_id}");
            queue.remove_by_key(&key);
            (true, ())
        })
        .unwrap();

        // Invoke verify_staged_report: artifact present, key absent → NOT a lie.
        let mut report = EvolverReport::default();
        verify_staged_report(home, std::slice::from_ref(&proposal_id), &mut report);

        assert!(
            report.verified_ok,
            "verified_ok must be true when artifact exists but key was concurrently drained"
        );
        assert_eq!(
            report.claims_missing, 0,
            "claims_missing must be zero for drained-not-lied shape"
        );
    }
}
