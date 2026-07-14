//! JV-SELF-03 â€” Auto-builder signal collector (async cron wrapper).
//!
//! Feeds the Collect â†’ Classify â†’ Propose (HERMES-06) â†’ Build â†’ Verify
//! (JV-SELF-01) â†’ Consolidate (JV-SELF-02) self-improvement loop.
//!
//! ## What it does
//!
//! Every tick the collector scans four data sources inside `spawn_blocking`:
//!
//! 1. **`idx_episode`** â€” most-recent `window_days` of raw-text events
//!    (`event_type = 0x01`). [`crate::reflection::topic_counts`] tokenises
//!    the corpus; any topic that exceeds `min_freq_threshold` appearances
//!    is a signal candidate.
//!
//! 2. **`idx_groundtruth`** (source IN `'synthesis-cron'`, `'jv-self-01'`) â€”
//!    lessons the synthesis and self-verify croons have previously written;
//!    used to classify signals as `ConfigChange` when a lesson overlaps the
//!    topic.
//!
//! 3. **`self_improve_log.json`** â€” the SkillOpt ledger; consulted to detect
//!    skills that were applied but scored badly (â†’ `PatchSkill`) or have not
//!    yet had their artifact verified on disk (â†’ `Escalate`).
//!
//! 4. **`trajectories/*.jsonl`** â€” HARNESS-02 session traces. Tool-call
//!    sequences supported by more than three independent sessions with
//!    confidence above 0.8 become pending skill proposals (when
//!    `propose_skills` is enabled) and emit `SKILL_DISTILL_CANDIDATE`.
//!
//! ## Output
//!
//! A [`CollectorReport`] is serialised atomically to
//! `~/.neoth/self_improvement_signals.json` so HERMES-06 can poll the
//! sidecar without compile-time coupling to this module.
//!
//! ## WAL frames
//!
//! - `0xBE SELF_IMPROVEMENT_COLLECTOR_STARTED` â€” emitted BEFORE
//!   `spawn_blocking`.
//! - `0xBF SELF_IMPROVEMENT_COLLECTOR_DONE` â€” emitted AFTER
//!   `spawn_blocking` returns.
//!
//! Both are written in async context, NOT inside `spawn_blocking`, because
//! [`crate::wal::writer::WalWriterHandle::append`] is async and requires the
//! tokio executor â€” calling from inside `spawn_blocking` would panic.
//!
//! ## Opt-in
//!
//! Disabled by default (`freedom.yaml::self_improvement_collector.enabled:
//! false`). Returns `None` when disabled â†’ no idle task is spawned.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::automation::SelfImprovementCollectorConfig;
use crate::wal::{
    EventFlags, HeaderBuilder,
    events::{
        EVENT_TYPE_EXTENDED, EVENT_TYPE_SELF_IMPROVEMENT_COLLECTOR_DONE,
        EVENT_TYPE_SELF_IMPROVEMENT_COLLECTOR_STARTED, ExtendedSubtype,
    },
    writer::WalWriterHandle,
};

// â”€â”€ Signal taxonomy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Minimum age in seconds a skill artifact must have existed on disk before
/// it is considered "verified deployed". A freshly written file (< 5 min old)
/// may still be partially written by a concurrent SkillOpt run; waiting 5
/// minutes is ample and keeps the check lockless.
const DEFAULT_ARTIFACT_MIN_AGE_SECS: u64 = 300;

/// Ledger score delta below which a skill is considered to have regressed and
/// warrants a `PatchSkill` signal. A negative delta means the accepted edit
/// made things worse (possible if the held-out gate was narrow).
const SCORE_REGRESSION_THRESHOLD: f64 = -0.05;

/// Maximum fraction of a topic's ledger-mention count that may be rejected
/// before the signal is escalated rather than edited. A rejection rate above
/// this suggests the topic is genuinely hard and needs operator attention.
const ESCALATE_REJECTION_RATE: f64 = 0.5;

// â”€â”€ Public types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single classified signal produced by one collector tick.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CollectorSignal {
    /// The named skill has a ledger score regression; a targeted prompt edit
    /// may help.
    PatchSkill { skill_id: String, reason: String },
    /// A specific prompt template or persona block should be edited to address
    /// the topic cluster.
    PromptEdit { target: String, reason: String },
    /// A configuration key appears to be the root cause; the operator should
    /// review it.
    ConfigChange { key: String, reason: String },
    /// The signal cannot be automatically resolved; operator attention needed.
    Escalate { reason: String },
}

/// GOLD-DELTA-13 â€” one advisory Babel-fitness assessment of an accepted
/// self-improvement change. Snapshot semantics: the report is rewritten
/// every tick, so a change is re-assessed each tick until it ages out of
/// the look-back â€” idempotent, not accumulating.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabelFitnessNote {
    /// The skill/persona the accepted ledger record changed.
    pub skill: String,
    /// When the change landed (ledger `at_unix`).
    pub change_ts: i64,
    /// `reinforce` / `flag` / `neutral` (see `analytics::babel::store`).
    pub verdict: String,
    pub before_median: f64,
    pub after_median: f64,
    pub collapses_after: u32,
}

/// Summary returned by one self-improvement collector tick. Written to
/// `~/.neoth/self_improvement_signals.json` after each pass.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectorReport {
    /// Classified signals produced this tick.
    pub signals: Vec<CollectorSignal>,
    /// GOLD-DELTA-13 â€” Babel B_d fitness assessments of recent accepted
    /// changes. ADVISORY ONLY: the collector reports; the operator's
    /// autonomy level governs what auto-applies downstream (same gate as
    /// every other self-improvement action).
    #[serde(default)]
    pub babel_fitness: Vec<BabelFitnessNote>,
    /// Number of distinct topics above `min_freq_threshold` in the episode window.
    pub topics_scanned: usize,
    /// Number of ground-truth lessons read from `idx_groundtruth`.
    pub lessons_read: usize,
    /// Number of `ImproveRecord` entries checked in the ledger.
    pub ledger_records_checked: usize,
    /// Number of skill artifacts checked for on-disk deployment.
    pub deployed_artifacts_checked: usize,
    /// GOLD-ADAPT-KB-03 candidates that passed the independent-session gate.
    #[serde(default)]
    pub distill_candidates: usize,
    /// Candidate proposals available in the operator review queue this tick.
    #[serde(default)]
    pub distill_proposals_staged: usize,
    /// Unix seconds when the report was written.
    pub ts_unix: i64,
}

// â”€â”€ Artifact-deployment check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Returns `true` when the skill artifact at `artifact_path` exists AND its
/// mtime is at least `min_age_secs` seconds in the past (i.e. a write has
/// settled). Purely filesystem-based â€” no locks needed.
pub fn is_verified_deployed(artifact_path: &Path, min_age_secs: u64) -> bool {
    let Ok(meta) = std::fs::metadata(artifact_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        // Platform does not report mtime (unusual but possible); treat as settled.
        return true;
    };
    let Ok(elapsed) = modified.elapsed() else {
        return false;
    };
    elapsed.as_secs() >= min_age_secs
}

// â”€â”€ HERMES-06 GAP-A: PromptEdit â†’ staged skill proposals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Iterate `report.signals`, pick every `PromptEdit`, forge a candidate skill
/// proposal from it via [`crate::daemon::skill_forge::build_proposal_from_collector_signal`],
/// and stage it in the OB-03 proactive review queue.
///
/// Called synchronously from the async tick after the sidecar write. IO is
/// ordinary blocking filesystem ops (same pattern as `forge_and_stage_dreams`
/// in `cli::dreaming_task`); the volume is tiny (â‰¤ `TOP_N_TOPICS` items) so
/// `spawn_blocking` is not required.
///
/// Best-effort: every error is logged at `warn` level, staging continues for
/// the remaining signals.
fn stage_prompt_edit_proposals(home: &Path, report: &CollectorReport, tick_ts_unix: i64) {
    use crate::daemon::skill_forge::build_proposal_from_collector_signal;
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::stage_and_enqueue;

    let queue_path = home.join("proactive_queue.json");
    // Locked loadâ†’mutateâ†’save; tolerates a corrupt file (same as the old
    // `unwrap_or_default()`) by logging + skipping the staging pass.
    match ProactiveQueue::modify(&queue_path, |queue| {
        let mut staged = 0usize;

        for signal in &report.signals {
            let (target, reason) = match signal {
                CollectorSignal::PromptEdit { target, reason } => {
                    (target.as_str(), reason.as_str())
                }
                // PatchSkill and Escalate require operator attention beyond a skill
                // YAML draft â€” skip them here.
                _ => continue,
            };
            let Some(proposal) = build_proposal_from_collector_signal(target, reason, tick_ts_unix)
            else {
                tracing::debug!(
                    topic = target,
                    "self_improvement_collector: PromptEdit topic un-slugifiable, skipping proposal"
                );
                continue;
            };
            match stage_and_enqueue(home, proposal, queue) {
                Ok((_, true)) => staged += 1,
                Ok((_, false)) => {} // already in queue (dedup by proposal id)
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = target,
                        "self_improvement_collector: proposal staging failed"
                    );
                }
            }
        }

        // Persist only when at least one new proposal was staged.
        (staged > 0, staged)
    }) {
        Ok(staged) if staged > 0 => tracing::info!(
            staged,
            "HERMES-06 GAP-A: staged PromptEdit skill proposal(s) for operator review"
        ),
        Ok(_) => {}
        Err(e) => warn!(
            error = %e,
            "self_improvement_collector: queue load/save failed, staging pass skipped"
        ),
    }
}

// â”€â”€ GOLD-ADAPT-KB-03: trajectory distill â†’ reviewed skill proposal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const DISTILL_MIN_SESSIONS: usize = 4;
const DISTILL_MIN_SEQUENCE_LEN: usize = 2;
const DISTILL_MIN_CONFIDENCE: f64 = 0.8;

#[derive(Debug, Clone, Copy, Default)]
struct DistillPassReport {
    candidates: usize,
    proposals_staged: usize,
}

fn distill_sequence_hash(sequence: &[String]) -> String {
    let mut hasher = Sha256::new();
    for tool in sequence {
        hasher.update((tool.len() as u64).to_le_bytes());
        hasher.update(tool.as_bytes());
    }
    hex::encode(hasher.finalize())
}

async fn run_distill_pass(
    home: &Path,
    propose_skills: bool,
    writer: &WalWriterHandle,
    ts_unix: i64,
) -> DistillPassReport {
    let trajectory_dir = home.join("trajectories");
    let candidates = match tokio::task::spawn_blocking(move || {
        let sessions = crate::cli::distill::read_trajectory_sessions(&trajectory_dir);
        crate::cli::distill::find_distill_candidates(
            &sessions,
            DISTILL_MIN_SESSIONS,
            DISTILL_MIN_SEQUENCE_LEN,
            DISTILL_MIN_CONFIDENCE,
        )
    })
    .await
    {
        Ok(candidates) => candidates,
        Err(error) => {
            warn!(error = %error, "KB-03 trajectory distill worker panicked");
            return DistillPassReport::default();
        }
    };

    let mut proposal_available = vec![false; candidates.len()];
    if propose_skills && !candidates.is_empty() {
        use crate::daemon::skill_forge::build_proposal_from_distill_pattern;
        use crate::proactive::ProactiveQueue;
        use crate::proactive::action_staging::stage_and_enqueue;

        let queue_path = home.join("proactive_queue.json");
        let result = ProactiveQueue::modify(&queue_path, |queue| {
            let mut newly_staged = 0usize;
            for (index, candidate) in candidates.iter().enumerate() {
                let Some(proposal) = build_proposal_from_distill_pattern(
                    &candidate.sequence,
                    candidate.occurrences,
                    candidate.supporting_sessions,
                    candidate.eligible_sessions,
                    candidate.confidence,
                    ts_unix,
                ) else {
                    continue;
                };
                match stage_and_enqueue(home, proposal, queue) {
                    Ok((_, is_new)) => {
                        proposal_available[index] = true;
                        newly_staged += is_new as usize;
                    }
                    Err(error) => warn!(
                        error = %error,
                        sequence_hash_sha256 = %distill_sequence_hash(&candidate.sequence),
                        "KB-03 distill proposal staging failed"
                    ),
                }
            }
            (newly_staged > 0, newly_staged)
        });
        if let Err(error) = result {
            warn!(error = %error, "KB-03 proactive queue update failed");
        }
    }

    for (index, candidate) in candidates.iter().enumerate() {
        let payload = serde_json::json!({
            "sequence_hash_sha256": distill_sequence_hash(&candidate.sequence),
            "sequence_len": candidate.sequence.len(),
            "occurrences": candidate.occurrences,
            "supporting_sessions": candidate.supporting_sessions,
            "eligible_sessions": candidate.eligible_sessions,
            "confidence_milli": (candidate.confidence * 1000.0).round() as u16,
            "proposal_staged": proposal_available[index],
            "ts_unix": ts_unix,
        });
        match serde_json::to_vec(&payload) {
            Ok(payload) => {
                let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
                    .event_subtype(ExtendedSubtype::SkillDistillCandidate as u8)
                    .build();
                if let Err(error) = writer.append(header, payload).await {
                    warn!(error = %error, "KB-03 SKILL_DISTILL_CANDIDATE WAL append failed");
                }
            }
            Err(error) => warn!(error = %error, "KB-03 candidate audit serialization failed"),
        }
    }

    DistillPassReport {
        candidates: candidates.len(),
        proposals_staged: proposal_available
            .into_iter()
            .filter(|available| ç¾¸¶‰Ëkºwµç@€€€€€€€¤ì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô(€€€±•Ğ¥¹Ñ•ÉÙ…°€ô½¹™¥œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤ì(€€€M½µ”¡Ñ½­¥¼èéÍÁ…İ¸¡…Íå¹Œµ½Ù”ì(€€€€€€€±•ĞµÕĞÑ¥­•È€ôÑ½­¥¼èéÑ¥µ”èé¥¹Ñ•ÉÙ…°¡¥¹Ñ•ÉÙ…°¤ì(€€€€€€€Ñ¥­•È¹Í•Ñ}µ¥ÍÍ•‘}Ñ¥­}‰•¡…Ù¥½È¡Ñ½­¥¼èéÑ¥µ”èé5¥ÍÍ•‘Q¥­	•¡…Ù¥½ÈèéM­¥À¤ì(€€€€€€€ÑÉ…¥¹œèé¥¹™¼„ (€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ì€ô¥¹Ñ•ÉÙ…°¹…Í}Í•Ì ¤°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌ€ô½¹™¥œ¹İ¥¹‘½İ}‘…åÌ°(€€€€€€€€€€€µ¥¹}™É•Å}Ñ¡É•Í¡½±€ô½¹™¥œ¹µ¥¹}™É•Å}Ñ¡É•Í¡½±°(€€€€€€€€€€€€‰Í•±˜µ¥µÁÉ½Ù•µ•¹Ğ½±±•Ñ½ÈÉ½¸±½½À½¹±¥¹”€¡)XµM1´ÀÌ¤ˆ°(€€€€€€€€¤ì(€€€€€€€±½½Àì(€€€€€€€€€€€Ñ¥­•È¹Ñ¥¬ ¤¹…İ…¥Ğì(€€€€€€€€€€€±•ĞÉ•Á½ÉĞ€ô(€€€€€€€€€€€€€€€µ…Ñ ÉÕ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}Ñ¥¬ ™‘‰}Á…Ñ °€™¡½µ”°½¹™¥œ°€™İÉ¥Ñ•È¤¹…İ…¥Ğì(€€€€€€€€€€€€€€€€€€€=¬¡É•Á½ÉĞ¤€ôøÉ•Á½ÉĞ°(€€€€€€€€€€€€€€€€€€€ÉÈ¡•ÉÉ½È¤€ôøì(€€€€€€€€€€€€€€€€€€€€€€€ÑÉ…¥¹œèé•ÉÉ½È„ (€€€€€€€€€€€€€€€€€€€€€€€€€€€•ÉÉ½È€ô€•™½Éµ…Ğ„ ‰í•ÉÉ½Èèôˆ¤°(€€€€€€€€€€€€€€€€€€€€€€€€€€€€‰Í•±˜µ¥µÁÉ½Ù•µ•¹Ğ½±±•Ñ½ÈÑ¥¬™…¥±•±½Í•ˆ(€€€€€€€€€€€€€€€€€€€€€€€€¤ì(€€€€€€€€€€€€€€€€€€€€€€€½¹Ñ¥¹Õ”ì(€€€€€€€€€€€€€€€€€€€ô(€€€€€€€€€€€€€€€ôì(€€€€€€€€€€€ÑÉ…¥¹œèé¥¹™¼„ (€€€€€€€€€€€€€€€Í¥¹…±Ì€ôÉ•Á½ÉĞ¹Í¥¹…±Ì¹±•¸ ¤°(€€€€€€€€€€€€€€€Ñ½Á¥Í}Í…¹¹•€ôÉ•Á½ÉĞ¹Ñ½Á¥Í}Í…¹¹•°(€€€€€€€€€€€€€€€±•ÍÍ½¹Í}É•…€ôÉ•Á½ÉĞ¹±•ÍÍ½¹Í}É•…°(€€€€€€€€€€€€€€€€‰Í•±˜µ¥µÁÉ½Ù•µ•¹Ğ½±±•Ñ½ÈÉ½¸Ñ¥¬½µÁ±•Ñ”ˆ°(€€€€€€€€€€€€¤ì(€€€€€€€€€€€€¼¼!I5L´ÀØ@µƒŠPÉÕ¸Ñ¡”…Á…‰¥±¥Ñä•Ù½±Ù•È¥¹±¥¹”°‰•ÍĞµ•™™½ÉĞ¸(€€€€€€€€€€€€¼¼Q¡”•Ù½±Ù•È…Ñ•ÌÍ¥¹…±Ì‰ä…ÕÑ¼µÍ…™”…±±½İ±¥ÍĞ°™½É•ÌÁÉ½Á½Í…±Ì°(€€€€€€€€€€€€¼¼¡•­Ì…ÉÑ¥™…Ğ‘•Á±½åµ•¹Ğ¥‘•µÁ½Ñ•¹ä°…¹ÍÑ…•Ì¥¹Ñ¼Ñ¡”ÁÉ½…Ñ¥Ù”(€€€€€€€€€€€€¼¼ÅÕ•Õ”¸ÉÉ½ÉÌ…É”±½•¥¹Í¥‘”ÉÕ¹}•Ù½±Ù•É}Á…ÍÌìÉ•ÍÕ±Ğ¥Ì‘É½ÁÁ•¸(€€€€€€€€€€€±•Ğ}•Ù½±Ù•È€ôÉ…Ñ”èé‘…•µ½¸èé…Á…‰¥±¥Ñå}•Ù½±Ù•ÈèéÉÕ¹}•Ù½±Ù•É}Á…ÍÌ (€€€€€€€€€€€€€€€€™¡½µ”°(€€€€€€€€€€€€€€€€™É•Á½ÉĞ°(€€€€€€€€€€€€€€€É…Ñ”èéÑ¥µ”èé¹½İ}Õ¹¥á}¤ØĞ ¤°(€€€€€€€€€€€€€€€M½µ” ™İÉ¥Ñ•È¤°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹…İ…¥Ğì(€€€€€€€ô(€€€ô¤¤)ô((¼¼ƒŠRŠR Q•ÍÑÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((m™œ¡Ñ•ÍĞ¥t)µ½Ñ•ÍÑÌì(€€€ÕÍ”ÍÕÁ•Èèè¨ì(€€€ÕÍ”É…Ñ”èé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€ÕÍ”É…Ñ”èéµ•µ½ÉäèéÍÑ½É”ì((€€€€¼¼ƒŠRŠR =1µ1Q´ÄÌƒŠP‰…‰•°™¥Ñ¹•ÍÌ¹½Ñ•ÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€™¸¥µÁÉ½Ù•}É•½É (€€€€€€€Í­¥±°è€™ÍÑÈ°(€€€€€€€…Ñ}Õ¹¥àè¤ØĞ°(€€€€€€€…•ÁÑ•è‰½½°°(€€€€¤€´øÉ…Ñ”èéÍ•±™}¥µÁÉ½Ù”èé%µÁÉ½Ù•I•½Éì(€€€€€€€É…Ñ”èéÍ•±™}¥µÁÉ½Ù”èé%µÁÉ½Ù•I•½Éì(€€€€€€€€€€€ÁÉ½Á½Í…±}¥è9½¹”°(€€€€€€€€€€€Í­¥±°èÍ­¥±°¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€…•ÁÑ•°(€€€€€€€€€€€Í½É•}‰•™½É”è€À¸Ô°(€€€€€€€€€€€Í½É•}…™Ñ•Èè€À¸Ø°(€€€€€€€€€€€ÍÕµµ…Éäè€‰Ñ•ÍĞ¡…¹”ˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€…Ñ}Õ¹¥à°(€€€€€€€ô(€€€ô((€€€€¼¼¼M••€ÄÔµµ¥¸İ¥¹‘½İÌ…É½Õ¹¡…¹•}ÑÍ€è€Ğ‰•™½É”…Ğ‰•™½É•}‰€°(€€€€¼¼¼€Ğ…™Ñ•È…Ğ…™Ñ•É}‰€¸(€€€™¸‰…‰•±}™¥Ñ¹•ÍÍ}‘ˆ¡¡…¹•}ÑÌè¤ØĞ°‰•™½É•}ˆè˜ØĞ°…™Ñ•É}ˆè˜ØĞ¤€´øÉÕÍÅ±¥Ñ”èé½¹¹•Ñ¥½¸ì(€€€€€€€±•Ğ½¹¸€ôÉÕÍÅ±¥Ñ”èé½¹¹•Ñ¥½¸èé½Á•¹}¥¹}µ•µ½Éä ¤¹•áÁ•Ğ ‰µ•´‘ˆˆ¤ì(€€€€€€€É…Ñ”èé…¹…±åÑ¥Ìèé‰…‰•°èéÍÑ½É”èé•¹ÍÕÉ•}Í¡•µ„ ™½¹¸¤¹•áÁ•Ğ ‰Í¡•µ„ˆ¤ì(€€€€€€€™½È¤¥¸€À¸¸Ñ¤ØĞì(€€€€€€€€€€€™½È€¡Ñ…œ°ÑÍ}•¹°ˆ¤¥¸l(€€€€€€€€€€€€€€€€ ‰ˆˆ°¡…¹•}ÑÌ€´¤€¨€äÀÀ°‰•™½É•}ˆ¤°(€€€€€€€€€€€€€€€€ ‰„ˆ°¡…¹•}ÑÌ€¬€äÀÀ€¬¤€¨€äÀÀ°…™Ñ•É}ˆ¤°(€€€€€€€€€€€tì(€€€€€€€€€€€€€€€½¹¸¹•á•ÕÑ” (€€€€€€€€€€€€€€€€€€€€‰%9MIP%9Q<¥‘á}‰…‰•±}İ¥¹‘½İÌ(€€€€€€€€€€€€€€€€€€€€€¡¥°Í•ÍÍ¥½¹}¥°İ¥¹‘½İ}Í•Ì°ÑÍ}ÍÑ…ÉĞ°ÑÍ}•¹°‰}‰½ÑÑ±•¹•¬°Ù…É¥…‰±•Ì¤(€€€€€€€€€€€€€€€€€€€€Y1UL€ üÄ°€„ÅˆÉŒÍÑ”Õ˜ØÀÜÄàœ°€äÀÀ°€üÈ°€üÌ°€üĞ°€íôœ¤ˆ°(€€€€€€€€€€€€€€€€€€€ÉÕÍÅ±¥Ñ”èéÁ…É…µÌ…m™½Éµ…Ğ„ ‰íÑ…õí¥ôˆ¤°ÑÍ}•¹€´€äÀÀ°ÑÍ}•¹°‰t°(€€€€€€€€€€€€€€€€¤(€€€€€€€€€€€€€€€€¹•áÁ•Ğ ‰Í••ˆ¤ì(€€€€€€€€€€€ô(€€€€€€€ô(€€€€€€€½¹¸(€€€ô((€€€€mÑ•ÍÑt(€€€™¸‰…‰•±}™¥Ñ¹•ÍÍ}¹½Ñ•Í}É•¥¹™½É•}…¹‘}™±…}İ¥Ñ¡}•Í…±…Ñ¥½¸ ¤ì(€€€€€€€±•Ğ¹½Ü€ô€Å|àÀÁ|ÄÀÁ|ÀÀÁ¤ØĞì(€€€€€€€±•Ğ¡…¹”€ô¹½Ü€´		1}%Q9MM}!=I%i=9}ML€´€ÄÀÀì€¼¼¡½É¥é½¸™Õ±±ä½‰Í•ÉÙ…‰±”(€€€€€€€€¼¼MÕÍÑ…¥¹•1=]H	}…™Ñ•ÈÑ¡”¡…¹”ƒŠHÉ•¥¹™½É”°¹¼Í¥¹…°¸(€€€€€€€±•Ğ½¹¸€ô‰…‰•±}™¥Ñ¹•ÍÍ}‘ˆ¡¡…¹”°€Ä¸À°€À¸Ô¤ì(€€€€€€€±•Ğ±•‘•È€ôÙ•Œ…m¥µÁÉ½Ù•}É•½É ‰Í­¥±°µ½½ˆ°¡…¹”°ÑÉÕ”¥tì(€€€€€€€±•Ğ€¡¹½Ñ•Ì°Í¥¹…±Ì¤€ô‰…‰•±}™¥Ñ¹•ÍÍ}¹½Ñ•Ì ™½¹¸°€™±•‘•È°¹½Ü¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡¹½Ñ•Ì¹±•¸ ¤°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡¹½Ñ•ÍlÁt¹Ù•É‘¥Ğ°€‰É•¥¹™½É”ˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡Í¥¹…±Ì¹¥Í}•µÁÑä ¤°€‰É•¥¹™½É”¹•Ù•È•Í…±…Ñ•Ìˆ¤ì((€€€€€€€€¼¼!%!H	}…™Ñ•ÈÑ¡”¡…¹”ƒŠH™±…œ€¬Í…±…Ñ”Í¥¹…°¸(€€€€€€€±•Ğ½¹¸€ô‰…‰•±}™¥Ñ¹•ÍÍ}‘ˆ¡¡…¹”°€À¸Ô°€Ä¸À¤ì(€€€€€€€±•Ğ±•‘•È€ôÙ•Œ…m¥µÁÉ½Ù•}É•½É ‰Í­¥±°µ‰…ˆ°¡…¹”°ÑÉÕ”¥tì(€€€€€€€±•Ğ€¡¹½Ñ•Ì°Í¥¹…±Ì¤€ô‰…‰•±}™¥Ñ¹•ÍÍ}¹½Ñ•Ì ™½¹¸°€™±•‘•È°¹½Ü¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡¹½Ñ•Ì¹±•¸ ¤°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡¹½Ñ•ÍlÁt¹Ù•É‘¥Ğ°€‰™±…œˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Í¥¹…±Ì¹±•¸ ¤°€Ä¤ì(€€€€€€€…ÍÍ•ÉĞ„¡µ…Ñ¡•Ì„ (€€€€€€€€€€€€™Í¥¹…±ÍlÁt°(€€€€€€€€€€€½±±•Ñ½ÉM¥¹…°èéÍ…±…Ñ”ìÉ•…Í½¸ô¥˜É•…Í½¸¹½¹Ñ…¥¹Ì ‰Í­¥±°µ‰…ˆ¤(€€€€€€€€¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸‰…‰•±}™¥Ñ¹•ÍÍ}¹½Ñ•Í}Í­¥Á}Õ¹…•ÁÑ•‘}Õ¹É¥Á•}…¹‘}Õ¹½‰Í•ÉÙ…‰±” ¤ì(€€€€€€€±•Ğ¹½Ü€ô€Å|àÀÁ|ÄÀÁ|ÀÀÁ¤ØĞì(€€€€€€€±•ĞÉ¥Á”€ô¹½Ü€´		1}%Q9MM}!=I%i=9}ML€´€ÄÀÀì(€€€€€€€±•Ğ½¹¸€ô‰…‰•±}™¥Ñ¹•ÍÍ}‘ˆ¡É¥Á”°€Ä¸À°€À¸Ô¤ì(€€€€€€€±•Ğ±•‘•È€ôÙ•Œ…l(€€€€€€€€€€€¥µÁÉ½Ù•}É•½É ‰É•©•Ñ•ˆ°É¥Á”°™…±Í”¤°€€€€€¼¼¹½Ğ…•ÁÑ•(€€€€€€€€€€€¥µÁÉ½Ù•}É•½É ‰Ñ½¼µ™É•Í ˆ°¹½Ü€´€ØÀ°ÑÉÕ”¤°€¼¼¡½É¥é½¸¹½Ğ½‰Í•ÉÙ…‰±”(€€€€€€€€€€€¥µÁÉ½Ù•}É•½É ‰…¹¥•¹Ğˆ°¹½Ü€´€ÌÀ€¨€àÙ|ĞÀÀ°ÑÉÕ”¤°€¼¼…•½ÕĞ(€€€€€€€tì(€€€€€€€±•Ğ€¡¹½Ñ•Ì°Í¥¹…±Ì¤€ô‰…‰•±}™¥Ñ¹•ÍÍ}¹½Ñ•Ì ™½¹¸°€™±•‘•È°¹½Ü¤ì(€€€€€€€…ÍÍ•ÉĞ„¡¹½Ñ•Ì¹¥Í}•µÁÑä ¤°€‰¹½Ñ¡¥¹œ…ÍÍ•ÍÍ…‰±”¥¸Ñ¡¥Ì±•‘•Èˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡Í¥¹…±Ì¹¥Í}•µÁÑä ¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR ½¹™¥œ‘•™…Õ±ÑÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸½¹™¥}‘•™…Õ±ÑÌ ¤ì(€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …™œ¹•¹…‰±•°€‰‘¥Í…‰±•‰ä‘•™…Õ±Ğˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€™œ¹¥¹Ñ•ÉÙ…±}Í•Ì°(€€€€€€€€€€€É…Ñ”èé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéU1Q}M1}%5AI=Y59Q}=11Q=I}%9QIY1}ML(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€™œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤°(€€€€€€€€€€€ÍÑèéÑ¥µ”èéÕÉ…Ñ¥½¸èé™É½µ}Í•Ì (€€€€€€€€€€€€€€€É…Ñ”èé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéU1Q}M1}%5AI=Y59Q}=11Q=I}%9QIY1}ML(€€€€€€€€€€€€¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡™œ¹İ¥¹‘½İ}‘…åÌ°€ÌÀ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡™œ¹µ¥¹}™É•Å}Ñ¡É•Í¡½±°€Ì¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸¥¹Ñ•ÉÙ…±}™±½½É}±…µÁÍ}é•É¼ ¤ì(€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€À°(€€€€€€€€€€€€¸¹•™…Õ±Ğèé‘•™…Õ±Ğ ¤(€€€€€€€ôì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡™œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤°ÍÑèéÑ¥µ”èéÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ØÀ¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÍÁ…İ¸‘¥Í…‰±•ƒŠH9½¹”ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÍÁ…İ¹}É•ÑÕÉ¹Í}¹½¹•}İ¡•¹}‘¥Í…‰±• ¤ì(€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€€€€€€€€€•¹…‰±•è™…±Í”°(€€€€€€€€€€€€¸¹•™…Õ±Ğèé‘•™…Õ±Ğ ¤(€€€€€€€ôì(€€€€€€€±•ĞÍ•}‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹İ…°ˆ¤ì(€€€€€€€±•Ğ€¡İÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéİ…°èéİÉ¥Ñ•ÈèéÍÁ…İ¸¡Í•œ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ¡…¹‘±”€ôÍÁ…İ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}±½½À (€€€€€€€€€€€™œ°(€€€€€€€€€€€€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€İÉ¥Ñ•È¹±½¹” ¤°(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉĞ„¡¡…¹‘±”¹¥Í}¹½¹” ¤°€‰‘¥Í…‰±•½¹™¥œµÕÍĞÉ•ÑÕÉ¸9½¹”ˆ¤ì(€€€€€€€‘É½À¡İÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…İ…¥Ğ¹½¬ ¤ì(€€€ô((€€€€¼¼ƒŠRŠR Ñ¥¬½¸•µÁÑä•µ¥ÑÌ]0™É…µ•Ì…¹é•É¼Í¥¹…±ÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ñ¥­}½¹}•µÁÑå}‘‰}•µ¥ÑÍ}İ…±}™É…µ•Í}…¹‘}é•É½}Í¥¹…±Ì ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€±•Ğ¡½µ”€ô‘¥È¹Á…Ñ  ¤¹Ñ½}Á…Ñ¡}‰Õ˜ ¤ì(€€€€€€€€¼¼É•…Ñ”Í¡•µ„¸(€€€€€€€‘É½À¡ÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤¤ì((€€€€€€€±•ĞÍ•}‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹İ…°ˆ¤ì(€€€€€€€±•Ğ€¡İÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéİ…°èéİÉ¥Ñ•ÈèéÍÁ…İ¸¡Í•œ¹±½¹” ¤¤¹Õ¹İÉ…À ¤ì((€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€±•ĞÉ•Á½ÉĞ€ôÉÕ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}Ñ¥¬ ™‘‰}Á…Ñ °€™¡½µ”°™œ°€™İÉ¥Ñ•È¤(€€€€€€€€€€€€¹…İ…¥Ğ(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì((€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉĞ¹Í¥¹…±Ì¹±•¸ ¤°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉĞ¹Ñ½Á¥Í}Í…¹¹•°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉĞ¹±•ÍÍ½¹Í}É•…°€À¤ì((€€€€€€€‘É½À¡İÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…İ…¥Ğ¹½¬ ¤ì((€€€€€€€€¼¼Y•É¥™ä‰½Ñ ]0™É…µ•Ì±…¹‘•¸(€€€€€€€±•Ğ‰åÑ•Ì€ôÍÑèé™ÌèéÉ•… ™Í•œ¤¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€‰åÑ•Ì¹İ¥¹‘½İÌ Ä¤¹…¹ä¡ñİğİlÁt€ôô€Áá	¤°(€€€€€€€€€€€€ˆÁá	MQIQµÕÍĞ‰”¥¸]0ˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€‰åÑ•Ì¹İ¥¹‘½İÌ Ä¤¹…¹ä¡ñİğİlÁt€ôô€Áá	¤°(€€€€€€€€€€€€ˆÁá	=9µÕÍĞ‰”¥¸]0ˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸¹¥¡Ñ±å}Ñ¥­}‘¥ÍÑ¥±±Í}É½ÍÍ}Í•ÍÍ¥½¹}Á…ÑÑ•É¹}…¹‘}…Õ‘¥ÑÍ}…¹‘¥‘…Ñ” ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€‘É½À¡ÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤¤ì(€€€€€€€±•ĞÑÉ…©•Ñ½É¥•Ì€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÑÉ…©•Ñ½É¥•Ìˆ¤ì(€€€€€€€ÍÑèé™ÌèéÉ•…Ñ•}‘¥É}…±° ™ÑÉ…©•Ñ½É¥•Ì¤¹Õ¹İÉ…À ¤ì(€€€€€€€™½È¥¹‘•à¥¸€À¸¸Ôì(€€€€€€€€€€€±•ĞÉ•½É€ôÉ…Ñ”èéµÀèé¡…É¹•ÍÌèéQÕÉ¹I•½Éì(€€€€€€€€€€€€€€€ÑÕÉ¸è€Ä°(€€€€€€€€€€€€€€€ÁÉ½µÁÑ}¡…Í è™½Éµ…Ğ„ ‰Í•ÍÍ¥½¸µí¥¹‘•áôˆ¤°(€€€€€€€€€€€€€€€ÁÉ½µÁÑ}±•¸è€ÄÀ°(€€€€€€€€€€€€€€€Ñ½½±}…±±ÌèÙ•Œ…l‰™¥±•ÍåÍÑ•´½É•…ˆ¹¥¹Ñ¼ ¤°€‰•‘¥Ñ½È½…ÁÁ±äˆ¹¥¹Ñ¼ ¥t°(€€€€€€€€€€€€€€€Ù•É‘¥Ğè€‰Ñ½½±}…±±Ìˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€€€€ÑÍ}Õ¹¥àè€Å|ÜÀÁ|ÀÀÁ|ÀÀÀ€¬¥¹‘•à°(€€€€€€€€€€€ôì(€€€€€€€€€€€ÍÑèé™ÌèéİÉ¥Ñ” (€€€€€€€€€€€€€€€ÑÉ…©•Ñ½É¥•Ì¹©½¥¸¡™½Éµ…Ğ„ ‰Í•ÍÍ¥½¸µí¥¹‘•áô¹©Í½¹°ˆ¤¤°(€€€€€€€€€€€€€€€™½Éµ…Ğ„ ‰íõq¸ˆ°Í•É‘•}©Í½¸èéÑ½}ÍÑÉ¥¹œ ™É•½É¤¹Õ¹İÉ…À ¤¤°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€ô((€€€€€€€±•ĞÍ•µ•¹Ğ€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰‘¥ÍÑ¥±°¹İ…°ˆ¤ì(€€€€€€€±•Ğ€¡İÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéİ…°èéİÉ¥Ñ•ÈèéÍÁ…İ¸¡Í•µ•¹Ğ¹±½¹” ¤¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±ÌèÑÉÕ”°(€€€€€€€€€€€€¸¹•™…Õ±Ğèé‘•™…Õ±Ğ ¤(€€€€€€€ôì(€€€€€€€±•ĞÉ•Á½ÉĞ€ôÉÕ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}Ñ¥¬ ™‘‰}Á…Ñ °‘¥È¹Á…Ñ  ¤°™œ°€™İÉ¥Ñ•È¤(€€€€€€€€€€€€¹…İ…¥Ğ(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉĞ¹‘¥ÍÑ¥±±}…¹‘¥‘…Ñ•Ì°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡É•Á½ÉĞ¹‘¥ÍÑ¥±±}ÁÉ½Á½Í…±Í}ÍÑ…•°€Ä¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÍÑèé™ÌèéÉ•…‘}‘¥È¡‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÁÉ½Á½Í…±Ìˆ¤¤(€€€€€€€€€€€€€€€€¹Õ¹İÉ…À ¤(€€€€€€€€€€€€€€€€¹½Õ¹Ğ ¤°(€€€€€€€€€€€€Ä(€€€€€€€€¤ì((€€€€€€€‘É½À¡İÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…İ…¥Ğ¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‰åÑ•Ì€ôÍÑèé™ÌèéÉ•…¡Í•µ•¹Ğ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÍ•µ•¹Ñ}¡•…‘•È€ôÉ…Ñ”èéİ…°èéÍ•µ•¹Ñ}¡•…‘•ÈèéÁ…ÉÍ•}Í•µ•¹Ñ}¡•…‘•È ™‰åÑ•Ì¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞµÕĞÕÉÍ½È€ôÍ•µ•¹Ñ}¡•…‘•È¹¡•…‘•É}±•¸ ¤ì(€€€€€€€±•ĞµÕĞ…¹‘¥‘…Ñ•}Á…å±½…€ô9½¹”ì(€€€€€€€İ¡¥±”ÕÉÍ½È€ğ‰åÑ•Ì¹±•¸ ¤ì(€€€€€€€€€€€±•Ğ™É…µ”€ôÉ…Ñ”èéİ…°èé™É…µ”èé‘•½‘•}™É…µ” ™‰åÑ•ÍmÕÉÍ½È¸¹t¤¹Õ¹İÉ…À ¤ì(€€€€€€€€€€€¥˜™É…µ”¹¡•…‘•È¹•Ù•¹Ñ}ÑåÁ”€ôôY9Q}QeA}aQ9(€€€€€€€€€€€€€€€€˜˜™É…µ”¹¡•…‘•È¹•Ù•¹Ñ}ÍÕ‰ÑåÁ”€ôôáÑ•¹‘•‘MÕ‰ÑåÁ”èéM­¥±±¥ÍÑ¥±±…¹‘¥‘…Ñ”…ÌÔà(€€€€€€€€€€€ì(€€€€€€€€€€€€€€€…¹‘¥‘…Ñ•}Á…å±½…€ô(€€€€€€€€€€€€€€€€€€€M½µ”¡Í•É‘•}©Í½¸èé™É½µ}Í±¥”èèñÍ•É‘•}©Í½¸èéY…±Õ”ø¡™É…µ”¹Á…å±½…¤¹Õ¹İÉ…À ¤¤ì(€€€€€€€€€€€ô(€€€€€€€€€€€ÕÉÍ½È€¬ô™É…µ”¹¡•…‘•È¹Ñ½Ñ…±}±•¸…ÌÕÍ¥é”ì(€€€€€€€ô(€€€€€€€±•ĞÁ…å±½…€ô…¹‘¥‘…Ñ•}Á…å±½…¹•áÁ•Ğ ‰…¹‘¥‘…Ñ”]0™É…µ”µÕÍĞ‰”ÁÉ•Í•¹Ğˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…å±½…‘l‰ÍÕÁÁ½ÉÑ¥¹}Í•ÍÍ¥½¹Ì‰t°€Ô¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…å±½…‘l‰•±¥¥‰±•}Í•ÍÍ¥½¹Ì‰t°€Ô¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…å±½…‘l‰½¹™¥‘•¹•}µ¥±±¤‰t°€ÄÀÀÀ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…å±½…‘l‰ÁÉ½Á½Í…±}ÍÑ…•‰t°ÑÉÕ”¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€Á…å±½…‘l‰Í•ÅÕ•¹•}¡…Í¡}Í¡„ÈÔØ‰t(€€€€€€€€€€€€€€€€¹…Í}ÍÑÈ ¤(€€€€€€€€€€€€€€€€¹•áÁ•Ğ ‰¡…Í ÍÑÉ¥¹œˆ¤(€€€€€€€€€€€€€€€€¹±•¸ ¤°(€€€€€€€€€€€€ØĞ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÍÁ…İ¸•¹…‰±•ƒŠHM½µ”°…‰½ÉÑÌ±•…¹±äƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÍÁ…İ¹}É•ÑÕÉ¹Í}Í½µ•}İ¡•¹}•¹…‰±•‘}…¹‘}…‰½ÉÑÍ}±•…¹±ä ¤ì(€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€ääå|äää°(€€€€€€€€€€€€¸¹•™…Õ±Ğèé‘•™…Õ±Ğ ¤(€€€€€€€ôì(€€€€€€€±•ĞÍ•}‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹İ…°ˆ¤ì(€€€€€€€±•Ğ€¡İÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéİ…°èéİÉ¥Ñ•ÈèéÍÁ…İ¸¡Í•œ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ¡…¹‘±”€ôÍÁ…İ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}±½½À (€€€€€€€€€€€™œ°(€€€€€€€€€€€€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°(€€€€€€€€€€€İÉ¥Ñ•È¹±½¹” ¤°(€€€€€€€€¤(€€€€€€€€¹•áÁ•Ğ ‰•¹…‰±•½¹™¥œµÕÍĞÉ•ÑÕÉ¸M½µ”ˆ¤ì(€€€€€€€¡…¹‘±”¹…‰½ÉĞ ¤ì(€€€€€€€±•Ğ|€ô¡…¹‘±”¹…İ…¥Ğì(€€€€€€€‘É½À¡İÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…İ…¥Ğ¹½¬ ¤ì(€€€ô((€€€€¼¼ƒŠRŠR ¥Í}Ù•É¥™¥•‘}‘•Á±½å•ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸¥Í}Ù•É¥™¥•‘}‘•Á±½å•‘}µ¥ÍÍ¥¹}Á…Ñ¡}É•ÑÕÉ¹Í}™…±Í” ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …¥Í}Ù•É¥™¥•‘}‘•Á±½å• (€€€€€€€€€€€A…Ñ èé¹•Ü ˆ½¹½¹•á¥ÍÑ•¹Ğ½Í­¥±°¹å…µ°ˆ¤°(€€€€€€€€€€€€À(€€€€€€€€¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸¥Í}Ù•É¥™¥•‘}‘•Á±½å•‘}•á¥ÍÑ¥¹}™¥±•}é•É½}…•}É•ÑÕÉ¹Í}ÑÉÕ” ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÀ€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Í­¥±°¹å…µ°ˆ¤ì(€€€€€€€ÍÑèé™ÌèéİÉ¥Ñ” ™À°ˆ‰•¹…‰±•èÑÉÕ”ˆ¤¹Õ¹İÉ…À ¤ì(€€€€€€€€¼¼µ¥¹}…•}Í•Ì€ô€ÀƒŠH•±…ÁÍ•…±İ…åÌ€øô€À¸(€€€€€€€…ÍÍ•ÉĞ„¡¥Í}Ù•É¥™¥•‘}‘•Á±½å• ™À°€À¤¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸¥Í}Ù•É¥™¥•‘}‘•Á±½å•‘}™É•Í¡}™¥±•}™…¥±Í}…•}¡•¬ ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÀ€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Í­¥±°¹å…µ°ˆ¤ì(€€€€€€€ÍÑèé™ÌèéİÉ¥Ñ” ™À°ˆ‰•¹…‰±•èÑÉÕ”ˆ¤¹Õ¹İÉ…À ¤ì(€€€€€€€€¼¼©ÕÍĞµİÉ¥ÑÑ•¸™¥±”İ½¸Ğ¡…Ù”•±…ÁÍ•€ääå|äääÍ•½¹‘Ì¸(€€€€€€€…ÍÍ•ÉĞ„ …¥Í}Ù•É¥™¥•‘}‘•Á±½å• ™À°€ääå|äää¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR Í¥‘•…ÈİÉ¥ÑÑ•¸½¸Ñ¥¬ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸Ñ¥­}İÉ¥Ñ•Í}Í¥‘•…É}©Í½¸ ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€±•Ğ¡½µ”€ô‘¥È¹Á…Ñ  ¤¹Ñ½}Á…Ñ¡}‰Õ˜ ¤ì(€€€€€€€‘É½À¡ÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤¤ì((€€€€€€€±•ĞÍ•}‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•ĞÍ•œ€ôÍ•}‘¥È¹Á…Ñ  ¤¹©½¥¸ ˆÀÀÀÀÀÄ¹İ…°ˆ¤ì(€€€€€€€±•Ğ€¡İÉ¥Ñ•È°©½¥¸¤€ôÉ…Ñ”èéİ…°èéİÉ¥Ñ•ÈèéÍÁ…İ¸¡Í•œ¤¹Õ¹İÉ…À ¤ì((€€€€€€€±•Ğ™œ€ôM•±™%µÁÉ½Ù•µ•¹Ñ½±±•Ñ½É½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€±•Ğ}É•Á½ÉĞ€ôÉÕ¹}Í•±™}¥µÁÉ½Ù•µ•¹Ñ}½±±•Ñ½É}Ñ¥¬ ™‘‰}Á…Ñ °€™¡½µ”°™œ°€™İÉ¥Ñ•È¤(€€€€€€€€€€€€¹…İ…¥Ğ(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì((€€€€€€€‘É½À¡İÉ¥Ñ•È¤ì(€€€€€€€©½¥¸¹…İ…¥Ğ¹½¬ ¤ì((€€€€€€€±•ĞÍ¥‘•…È€ô¡½µ”¹©½¥¸ ‰Í•±™}¥µÁÉ½Ù•µ•¹Ñ}Í¥¹…±Ì¹©Í½¸ˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡Í¥‘•…È¹•á¥ÍÑÌ ¤°€‰Í¥‘•…È)M=8µÕÍĞ‰”İÉ¥ÑÑ•¸ˆ¤ì(€€€€€€€±•ĞÁ…ÉÍ•è½±±•Ñ½ÉI•Á½ÉĞ€ô(€€€€€€€€€€€Í•É‘•}©Í½¸èé™É½µ}Í±¥” ™ÍÑèé™ÌèéÉ•… ™Í¥‘•…È¤¹Õ¹İÉ…À ¤¤¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Á…ÉÍ•¹Í¥¹…±Ì¹±•¸ ¤°€À¤ì(€€€ô)ô(