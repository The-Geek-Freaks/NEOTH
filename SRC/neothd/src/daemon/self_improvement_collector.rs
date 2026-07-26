//! JV-SELF-03 — Auto-builder signal collector (async cron wrapper).
//!
//! Feeds the Collect → Classify → Propose (HERMES-06) → Build → Verify
//! (JV-SELF-01) → Consolidate (JV-SELF-02) self-improvement loop.
//!
//! ## What it does
//!
//! Every tick the collector scans four data sources inside `spawn_blocking`:
//!
//! 1. **`idx_episode`** — most-recent `window_days` of raw-text events
//!    (`event_type = 0x01`). [`crate::reflection::topic_counts`] tokenises
//!    the corpus; any topic that exceeds `min_freq_threshold` appearances
//!    is a signal candidate.
//!
//! 2. **`idx_groundtruth`** (source IN `'synthesis-cron'`, `'jv-self-01'`) —
//!    lessons the synthesis and self-verify croons have previously written;
//!    used to classify signals as `ConfigChange` when a lesson overlaps the
//!    topic.
//!
//! 3. **`self_improve_log.json`** — the SkillOpt ledger; consulted to detect
//!    skills that were applied but scored badly (→ `PatchSkill`) or have not
//!    yet had their artifact verified on disk (→ `Escalate`).
//!
//! 4. **`trajectories/*.jsonl`** — HARNESS-02 session traces. Tool-call
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
//! - `0xBE SELF_IMPROVEMENT_COLLECTOR_STARTED` — emitted BEFORE
//!   `spawn_blocking`.
//! - `0xBF SELF_IMPROVEMENT_COLLECTOR_DONE` — emitted AFTER
//!   `spawn_blocking` returns.
//!
//! Both are written in async context, NOT inside `spawn_blocking`, because
//! [`crate::wal::writer::WalWriterHandle::append`] is async and requires the
//! tokio executor — calling from inside `spawn_blocking` would panic.
//!
//! ## Opt-in
//!
//! Disabled by default (`freedom.yaml::self_improvement_collector.enabled:
//! false`). Returns `None` when disabled → no idle task is spawned.

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

// ── Signal taxonomy ──────────────────────────────────────────────────────────

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

// ── Public types ─────────────────────────────────────────────────────────────

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

/// GOLD-DELTA-13 — one advisory Babel-fitness assessment of an accepted
/// self-improvement change. Snapshot semantics: the report is rewritten
/// every tick, so a change is re-assessed each tick until it ages out of
/// the look-back — idempotent, not accumulating.
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
    /// GOLD-DELTA-13 — Babel B_d fitness assessments of recent accepted
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

// ── Artifact-deployment check ────────────────────────────────────────────────

/// Returns `true` when the skill artifact at `artifact_path` exists AND its
/// mtime is at least `min_age_secs` seconds in the past (i.e. a write has
/// settled). Purely filesystem-based — no locks needed. The decision logic is
/// factored into [`is_deployment_settled`] so every branch is deterministically
/// testable without a real filesystem.
pub fn is_verified_deployed(skills_root: &Path, skill_id: &str, min_age_secs: u64) -> bool {
    // GOLD-R3-11: read the artifact mtime through the capability-bound, no-follow
    // store instead of an ambient `<root>/<id>/skill.yaml` join + `fs::metadata`,
    // so a symlink / junction / reparse point planted at the skill id or the file
    // cannot redirect this "already deployed" check onto a foreign file. Missing
    // root / skill / artifact or any store error → not-deployed (fail closed,
    // consistent with `is_deployment_settled`). No mutation lock is taken: this is
    // a best-effort hint and reading a fresh mtime mid-install only yields
    // "not settled" (the conservative direction), so the lock's 5s spin is kept
    // off the collector/evolver tick path.
    let Ok(Some(root)) =
        crate::skills::store::open_bound_directory(skills_root, false, "skills root")
    else {
        return false;
    };
    let skill_display = root.display_path.join(skill_id);
    let Ok(skill_dir) = crate::skills::store::open_real_child_dir(
        &root.dir,
        std::ffi::OsStr::new(skill_id),
        &skill_display,
    ) else {
        return false;
    };
    let file_display = skill_display.join("skill.yaml");
    let Ok(file) = crate::skills::store::open_regular_file(
        &skill_dir,
        std::ffi::OsStr::new("skill.yaml"),
        &file_display,
    ) else {
        return false;
    };
    let modified = modified_time_of(&file);
    is_deployment_settled(
        modified,
        std::time::SystemTime::now(),
        std::time::Duration::from_secs(min_age_secs),
    )
}

/// The artifact mtime as the std clock type, or `None` when the platform or
/// filesystem does not report one.
///
/// Split out because THIS is where the `None` the fail-closed contract depends
/// on is produced: [`is_deployment_settled`] has deterministic coverage for
/// every branch, but the mapping that can feed it was only exercised through
/// real files that always have an mtime. A later "simplification" to
/// `unwrap_or(UNIX_EPOCH)` here would silently flip the whole contract from
/// fail-closed to fail-open while every existing test stayed green.
fn modified_time_of(file: &cap_std::fs::File) -> Option<std::time::SystemTime> {
    // cap-std reports a `cap_std::time::SystemTime`; convert to the std clock
    // type the pure decision helper works with. Never substitute a default.
    file.metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .map(|time| time.into_std())
}

/// Pure deployment-age decision, split from the filesystem calls so the
/// GOLD-R3-11 regression contract can exercise every branch deterministically.
///
/// `modified` is `None` when the platform/filesystem does not report an mtime.
/// All uncertainty fails CLOSED (not-deployed): a missing mtime, or a mtime in
/// the future (clock skew / a just-touched file), both yield `false` so an
/// unprovable "settled" state is escalated to the operator rather than treated
/// as deployed. Only a real mtime at least `min_age` in the past returns `true`.
fn is_deployment_settled(
    modified: Option<std::time::SystemTime>,
    now: std::time::SystemTime,
    min_age: std::time::Duration,
) -> bool {
    let Some(modified) = modified else {
        // mtime unavailable → cannot prove the write has settled.
        return false;
    };
    match now.duration_since(modified) {
        Ok(elapsed) => elapsed >= min_age,
        // `modified` is in the future relative to `now` → not settled.
        Err(_) => false,
    }
}

/// Is the artifact possibly already deployed — i.e. can we NOT prove it is
/// absent or fresh?
///
/// [`is_verified_deployed`] fails closed toward "not deployed", which is the
/// conservative answer for a caller whose `false` branch ESCALATES to the
/// operator. For a caller whose `false` branch instead does more work — the
/// capability evolver stages a proposal — the same `false` is the RISKY
/// direction: on a filesystem that reports no mtime it would re-stage proposals
/// for artifacts that are already on disk, forever.
///
/// Same evidence, opposite default: only a provable absence (no root, no skill,
/// no artifact) answers `false` here. An unreadable mtime is "unknown", and
/// unknown means don't do more work.
pub fn is_possibly_deployed(skills_root: &Path, skill_id: &str, min_age_secs: u64) -> bool {
    let Ok(Some(root)) =
        crate::skills::store::open_bound_directory(skills_root, false, "skills root")
    else {
        return false;
    };
    let skill_display = root.display_path.join(skill_id);
    let Ok(skill_dir) = crate::skills::store::open_real_child_dir(
        &root.dir,
        std::ffi::OsStr::new(skill_id),
        &skill_display,
    ) else {
        return false;
    };
    let file_display = skill_display.join("skill.yaml");
    let Ok(file) = crate::skills::store::open_regular_file(
        &skill_dir,
        std::ffi::OsStr::new("skill.yaml"),
        &file_display,
    ) else {
        return false;
    };
    // The artifact exists. Only a mtime we can read AND that is younger than
    // the settle window proves it is still in flight; anything else counts as
    // deployed for the purpose of "should I stage more work?".
    match modified_time_of(&file) {
        Some(modified) => is_deployment_settled(
            Some(modified),
            std::time::SystemTime::now(),
            std::time::Duration::from_secs(min_age_secs),
        ),
        None => true,
    }
}

// ── HERMES-06 GAP-A: PromptEdit → staged skill proposals ────────────────────

/// Iterate `report.signals`, pick every `PromptEdit`, forge a candidate skill
/// proposal from it via [`crate::daemon::skill_forge::build_proposal_from_collector_signal`],
/// and stage it in the OB-03 proactive review queue.
///
/// Called synchronously from the async tick after the sidecar write. IO is
/// ordinary blocking filesystem ops (same pattern as `forge_and_stage_dreams`
/// in `cli::dreaming_task`); the volume is tiny (≤ `TOP_N_TOPICS` items) so
/// `spawn_blocking` is not required.
///
/// Best-effort: every error is logged at `warn` level, staging continues for
/// the remaining signals.
fn stage_prompt_edit_proposals(home: &Path, report: &CollectorReport, tick_ts_unix: i64) {
    use crate::daemon::skill_forge::build_proposal_from_collector_signal;
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::stage_and_enqueue;

    let queue_path = home.join("proactive_queue.json");
    // Locked load→mutate→save; tolerates a corrupt file (same as the old
    // `unwrap_or_default()`) by logging + skipping the staging pass.
    match ProactiveQueue::modify(&queue_path, |queue| {
        let mut staged = 0usize;

        for signal in &report.signals {
            let (target, reason) = match signal {
                CollectorSignal::PromptEdit { target, reason } => {
                    (target.as_str(), reason.as_str())
                }
                // PatchSkill and Escalate require operator attention beyond a skill
                // YAML draft — skip them here.
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

// ── GOLD-ADAPT-KB-03: trajectory distill → reviewed skill proposal ──────────

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
            .filter(|available| *available)
            .count(),
    }
}

// ── WAL emit helper ──────────────────────────────────────────────────────────

/// Emit one WAL frame (best-effort). A write failure is logged at `error`
/// level but never propagates — audit loss is visible via `neoth monitor`.
async fn emit(
    writer: &WalWriterHandle,
    event_type: u8,
    payload: serde_json::Value,
    label: &'static str,
) {
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %e,
                "self_improvement_collector: serialize WAL payload failed"
            );
            return;
        }
    };
    let header = HeaderBuilder::new(event_type, &bytes)
        .flags(EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, bytes).await {
        tracing::error!(
            audit_loss = true,
            event = label,
            error = %e,
            "self_improvement_collector: WAL frame lost"
        );
    }
}

// ── Blocking tick logic ──────────────────────────────────────────────────────

/// Inner synchronous tick — runs inside `spawn_blocking` so that rusqlite
/// `Connection` (which is `!Send`) never crosses an await point.
fn tick_inner(
    db_path: &Path,
    home: &Path,
    cfg: SelfImprovementCollectorConfig,
    ts_unix: i64,
) -> anyhow::Result<CollectorReport> {
    // ── 1. Open the views DB ─────────────────────────────────────────────────
    let conn = match crate::memory::store::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "self_improvement_collector: open db failed");
            return Ok(CollectorReport {
                ts_unix,
                ..Default::default()
            });
        }
    };

    // ── 2. Query idx_episode for raw-text events in the look-back window ─────
    let window_cutoff_ns = {
        let window_secs = cfg.window_days.saturating_mul(86_400);
        let now_ns = crate::time::now_unix_ns_i64();
        now_ns - (window_secs as i64).saturating_mul(1_000_000_000)
    };

    let texts: Vec<String> = {
        let mut stmt = match conn.prepare(
            "SELECT text FROM idx_episode \
             WHERE event_type = 1 AND ts_ns >= ?1 \
             ORDER BY ts_ns ASC",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "self_improvement_collector: prepare episode query failed");
                return Ok(CollectorReport {
                    ts_unix,
                    ..Default::default()
                });
            }
        };
        match stmt.query_map(rusqlite::params![window_cutoff_ns], |row| {
            row.get::<_, String>(0)
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                warn!(error = %e, "self_improvement_collector: episode query failed");
                return Ok(CollectorReport {
                    ts_unix,
                    ..Default::default()
                });
            }
        }
    };

    // ── 3. Count topics ──────────────────────────────────────────────────────
    let topic_map = crate::reflection::topic_counts(&texts);
    let candidate_topics: Vec<(String, usize)> = {
        let mut v: Vec<(String, usize)> = topic_map
            .into_iter()
            .filter(|(_, count)| *count >= cfg.min_freq_threshold as usize)
            .collect();
        // Deterministic order: highest count first, then alphabetical.
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    let topics_scanned = candidate_topics.len();

    // ── 4. Query idx_groundtruth lessons ────────────────────────────────────
    let lessons: Vec<String> = {
        match conn.prepare(
            "SELECT statement FROM idx_groundtruth \
             WHERE source IN ('synthesis-cron', 'jv-self-01') \
             ORDER BY id DESC \
             LIMIT 500",
        ) {
            Err(e) => {
                warn!(error = %e, "self_improvement_collector: prepare lessons query failed");
                vec![]
            }
            Ok(mut stmt) => match stmt.query_map([], |row| row.get::<_, String>(0)) {
                Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                Err(_) => vec![],
            },
        }
    };
    let lessons_read = lessons.len();

    // ── 5. Load SkillOpt ledger ──────────────────────────────────────────────
    let ledger = crate::self_improve::load_ledger(home)
        .context("self_improvement_collector: load SkillOpt ledger")?;
    let ledger_records_checked = ledger.len();

    // ── 5b. GOLD-DELTA-13 — Babel fitness of recent accepted changes ─────────
    let (babel_fitness, mut babel_signals) = babel_fitness_notes(&conn, &ledger, ts_unix);

    // ── 6. Classify signals ──────────────────────────────────────────────────
    let mut signals = Vec::new();
    let mut deployed_artifacts_checked: usize = 0;

    // Build a quick lookup: skill_id → ledger records for that skill.
    let mut skill_ledger: std::collections::HashMap<
        String,
        Vec<&crate::self_improve::ImproveRecord>,
    > = std::collections::HashMap::new();
    for rec in &ledger {
        skill_ledger.entry(rec.skill.clone()).or_default().push(rec);
    }

    let skill_root = home.join("skills");

    for (topic, count) in &candidate_topics {
        // Check if the topic maps to a known skill with a score regression.
        let mut classified = false;

        // Score-regression check: any skill whose name contains the topic token
        // AND whose most-recent accepted record has a negative delta below
        // SCORE_REGRESSION_THRESHOLD.
        for (skill_id, records) in &skill_ledger {
            if !skill_id.to_ascii_lowercase().contains(topic.as_str()) {
                continue;
            }
            // Most-recent record (ledger is oldest-first; pick last accepted).
            let latest = records
                .iter()
                .filter(|r| r.accepted)
                .max_by_key(|r| r.at_unix);
            let Some(rec) = latest else { continue };
            let delta = rec.score_after - rec.score_before;
            if delta < SCORE_REGRESSION_THRESHOLD {
                // Check artifact is deployed before recommending a patch — read
                // through the capability-bound store (GOLD-R3-11).
                deployed_artifacts_checked += 1;
                if !is_verified_deployed(&skill_root, skill_id, DEFAULT_ARTIFACT_MIN_AGE_SECS) {
                    signals.push(CollectorSignal::Escalate {
                        reason: format!(
                            "skill '{skill_id}' artifact not yet verified deployed \
                             (topic '{topic}', count {count})"
                        ),
                    });
                } else {
                    signals.push(CollectorSignal::PatchSkill {
                        skill_id: skill_id.clone(),
                        reason: format!(
                            "score regression {delta:.3} below threshold \
                             (topic '{topic}', count {count})"
                        ),
                    });
                }
                classified = true;
                break;
            }
        }
        if classified {
            continue;
        }

        // Lesson-overlap check: if any stored lesson text contains the topic,
        // classify as ConfigChange (an operator-visible lesson relates to this
        // topic cluster → likely a config or framing issue, not a skill gap).
        let lesson_hit = lessons
            .iter()
            .any(|l| l.to_ascii_lowercase().contains(topic.as_str()));
        if lesson_hit {
            signals.push(CollectorSignal::ConfigChange {
                key: topic.clone(),
                reason: format!(
                    "lesson overlap for topic '{topic}' (count {count}); \
                     review freedom.yaml or operator preset"
                ),
            });
            classified = true;
        }
        if classified {
            continue;
        }

        // Rejection-rate check: topics mentioned often but rejected by SkillOpt
        // repeatedly are better escalated than auto-patched.
        let total_for_topic: usize = skill_ledger
            .values()
            .flat_map(|recs| recs.iter())
            .filter(|r| r.skill.to_ascii_lowercase().contains(topic.as_str()))
            .count();
        let rejected_for_topic: usize = skill_ledger
            .values()
            .flat_map(|recs| recs.iter())
            .filter(|r| !r.accepted && r.skill.to_ascii_lowercase().contains(topic.as_str()))
            .count();
        let rejection_rate = if total_for_topic > 0 {
            rejected_for_topic as f64 / total_for_topic as f64
        } else {
            0.0
        };

        if rejection_rate > ESCALATE_REJECTION_RATE {
            signals.push(CollectorSignal::Escalate {
                reason: format!(
                    "topic '{topic}' (count {count}) has rejection rate {rejection_rate:.2} \
                     — operator review recommended"
                ),
            });
        } else {
            signals.push(CollectorSignal::PromptEdit {
                target: topic.clone(),
                reason: format!(
                    "frequent topic '{topic}' ({count} episodes in window) \
                     with no existing skill coverage"
                ),
            });
        }
    }

    signals.append(&mut babel_signals);

    Ok(CollectorReport {
        signals,
        babel_fitness,
        topics_scanned,
        lessons_read,
        ledger_records_checked,
        deployed_artifacts_checked,
        ts_unix,
        ..Default::default()
    })
}

// ── GOLD-DELTA-13 — Babel fitness assessment ─────────────────────────────────

/// Horizon per side of a change (2 h = 8 primary 15-min windows).
const BABEL_FITNESS_HORIZON_SECS: i64 = 7200;
/// Changes older than this age out of the per-tick re-assessment.
const BABEL_FITNESS_LOOKBACK_SECS: i64 = 7 * 86_400;

/// Assess every accepted ledger change whose after-horizon is fully
/// observable: the Babel B_d trend around the change becomes an ADVISORY
/// note, and a `Flag` verdict additionally becomes an `Escalate` signal
/// (operator attention — never an automatic revert). Best-effort: a query
/// failure skips that record with a warn.
fn babel_fitness_notes(
    conn: &rusqlite::Connection,
    ledger: &[crate::self_improve::ImproveRecord],
    now: i64,
) -> (Vec<BabelFitnessNote>, Vec<CollectorSignal>) {
    use crate::analytics::babel::store::{FitnessVerdict, babel_fitness};
    let mut notes = Vec::new();
    let mut signals = Vec::new();
    for rec in ledger {
        if !rec.accepted
            || rec.at_unix < now - BABEL_FITNESS_LOOKBACK_SECS
            || rec.at_unix + BABEL_FITNESS_HORIZON_SECS > now
        {
            continue;
        }
        let fitness = match babel_fitness(conn, rec.at_unix, BABEL_FITNESS_HORIZON_SECS) {
            Ok(Some(f)) => f,
            Ok(None) => continue, // too few windows on a side — unobservable
            Err(e) => {
                warn!(error = %e, skill = %rec.skill, "babel fitness query failed");
                continue;
            }
        };
        let verdict = fitness.verdict();
        if verdict == FitnessVerdict::Flag {
            signals.push(CollectorSignal::Escalate {
                reason: format!(
                    "babel fitness FLAG on '{}' (changed at {}): median b_bottleneck \
                     {:.4} -> {:.4}, {} collapse(s) in the 2h horizon — review the change",
                    rec.skill,
                    rec.at_unix,
                    fitness.before_median,
                    fitness.after_median,
                    fitness.collapses_after
                ),
            });
        }
        notes.push(BabelFitnessNote {
            skill: rec.skill.clone(),
            change_ts: rec.at_unix,
            verdict: verdict.as_str().to_string(),
            before_median: fitness.before_median,
            after_median: fitness.after_median,
            collapses_after: fitness.collapses_after,
        });
    }
    (notes, signals)
}

// ── Public async tick ────────────────────────────────────────────────────────

/// One self-improvement collector tick:
/// 1. Emits `0xBE SELF_IMPROVEMENT_COLLECTOR_STARTED`.
/// 2. Runs [`tick_inner`] inside `spawn_blocking` (rusqlite `Connection` is
///    `!Send`).
/// 3. Writes the [`CollectorReport`] atomically to
///    `~/.neoth/self_improvement_signals.json`.
/// 4. Emits `0xBF SELF_IMPROVEMENT_COLLECTOR_DONE`.
///
/// Missing state remains a valid first-run condition. Corrupt/unreadable
/// self-improvement state and sidecar persistence failures are returned so a
/// caller cannot mistake them for a healthy zero-signal tick.
pub async fn run_self_improvement_collector_tick(
    db_path: &Path,
    home: &Path,
    cfg: SelfImprovementCollectorConfig,
    writer: &WalWriterHandle,
) -> anyhow::Result<CollectorReport> {
    let ts_unix = crate::time::now_unix_i64();

    emit(
        writer,
        EVENT_TYPE_SELF_IMPROVEMENT_COLLECTOR_STARTED,
        serde_json::json!({
            "window_days": cfg.window_days,
            "min_freq_threshold": cfg.min_freq_threshold,
            "ts_unix": ts_unix,
        }),
        "SELF_IMPROVEMENT_COLLECTOR_STARTED",
    )
    .await;

    let db = db_path.to_path_buf();
    let home_buf = home.to_path_buf();

    let mut report = tokio::task::spawn_blocking(move || tick_inner(&db, &home_buf, cfg, ts_unix))
        .await
        .context("self_improvement_collector: blocking tick task failed")??;

    let distill = run_distill_pass(home, cfg.propose_skills, writer, ts_unix).await;
    report.distill_candidates = distill.candidates;
    report.distill_proposals_staged = distill.proposals_staged;

    // Write the sidecar atomically so HERMES-06 can poll it.
    let sidecar_path = home.join("self_improvement_signals.json");
    let sidecar = serde_json::to_vec_pretty(&report)
        .context("self_improvement_collector: serialize sidecar")?;
    crate::util::atomic_write::atomic_write_private(&sidecar_path, &sidecar)
        .with_context(|| format!("write collector sidecar {}", sidecar_path.display()))?;

    // HERMES-06 GAP-A: convert PromptEdit signals into staged skill proposals.
    // Only PromptEdit signals map cleanly to a skill draft — PatchSkill and
    // Escalate need operator attention beyond what a skill YAML can address.
    // Best-effort: proposal staging errors are logged, never propagated.
    if cfg.propose_skills {
        stage_prompt_edit_proposals(home, &report, ts_unix);
    }

    let ts_unix_done = crate::time::now_unix_i64();
    emit(
        writer,
        EVENT_TYPE_SELF_IMPROVEMENT_COLLECTOR_DONE,
        serde_json::json!({
            "signals": report.signals.len(),
            "topics_scanned": report.topics_scanned,
            "lessons_read": report.lessons_read,
            "ledger_records_checked": report.ledger_records_checked,
            "deployed_artifacts_checked": report.deployed_artifacts_checked,
            "distill_candidates": report.distill_candidates,
            "distill_proposals_staged": report.distill_proposals_staged,
            "ts_unix": ts_unix_done,
        }),
        "SELF_IMPROVEMENT_COLLECTOR_DONE",
    )
    .await;

    Ok(report)
}

// ── Spawn loop ────────────────────────────────────────────────────────────────

/// Spawn the self-improvement collector cron loop as a background tokio task.
/// Returns `None` when `config.enabled == false` — opt-out operators carry
/// no idle task.
pub fn spawn_self_improvement_collector_loop(
    config: SelfImprovementCollectorConfig,
    db_path: PathBuf,
    home: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!(
            "self-improvement collector cron disabled \
             (self_improvement_collector.enabled = false)"
        );
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            window_days = config.window_days,
            min_freq_threshold = config.min_freq_threshold,
            "self-improvement collector cron loop online (JV-SELF-03)",
        );
        loop {
            ticker.tick().await;
            let report =
                match run_self_improvement_collector_tick(&db_path, &home, config, &writer).await {
                    Ok(report) => report,
                    Err(error) => {
                        tracing::error!(
                            error = %format!("{error:#}"),
                            "self-improvement collector tick failed closed"
                        );
                        continue;
                    }
                };
            tracing::info!(
                signals = report.signals.len(),
                topics_scanned = report.topics_scanned,
                lessons_read = report.lessons_read,
                "self-improvement collector cron tick complete",
            );
            // HERMES-06 GAP-B — run the capability evolver inline, best-effort.
            // The evolver gates signals by auto-safe allowlist, forges proposals,
            // checks artifact deployment idempotency, and stages into the proactive
            // queue. Errors are logged inside run_evolver_pass; result is dropped.
            let _evolver = crate::daemon::capability_evolver::run_evolver_pass(
                &home,
                &report,
                crate::time::now_unix_i64(),
                Some(&writer),
            )
            .await;
        }
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::automation::SelfImprovementCollectorConfig;
    use crate::memory::store;

    // ── GOLD-DELTA-13 — babel fitness notes ──────────────────────────────────

    fn improve_record(
        skill: &str,
        at_unix: i64,
        accepted: bool,
    ) -> crate::self_improve::ImproveRecord {
        crate::self_improve::ImproveRecord {
            proposal_id: None,
            skill: skill.to_string(),
            accepted,
            score_before: 0.5,
            score_after: 0.6,
            summary: "test change".to_string(),
            at_unix,
        }
    }

    /// Seed 15-min windows around `change_ts`: 4 before at `before_b`,
    /// 4 after at `after_b`.
    fn babel_fitness_db(change_ts: i64, before_b: f64, after_b: f64) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        crate::analytics::babel::store::ensure_schema(&conn).expect("schema");
        for i in 0..4i64 {
            for (tag, ts_end, b) in [
                ("b", change_ts - i * 900, before_b),
                ("a", change_ts + 900 + i * 900, after_b),
            ] {
                conn.execute(
                    "INSERT INTO idx_babel_windows
                     (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables)
                     VALUES (?1, 'a1b2c3d4e5f60718', 900, ?2, ?3, ?4, '{}')",
                    rusqlite::params![format!("{tag}{i}"), ts_end - 900, ts_end, b],
                )
                .expect("seed");
            }
        }
        conn
    }

    #[test]
    fn babel_fitness_notes_reinforce_and_flag_with_escalation() {
        let now = 1_800_100_000i64;
        let change = now - BABEL_FITNESS_HORIZON_SECS - 100; // horizon fully observable
        // Sustained LOWER B_d after the change → reinforce, no signal.
        let conn = babel_fitness_db(change, 1.0, 0.5);
        let ledger = vec![improve_record("skill-good", change, true)];
        let (notes, signals) = babel_fitness_notes(&conn, &ledger, now);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].verdict, "reinforce");
        assert!(signals.is_empty(), "reinforce never escalates");

        // HIGHER B_d after the change → flag + Escalate signal.
        let conn = babel_fitness_db(change, 0.5, 1.0);
        let ledger = vec![improve_record("skill-bad", change, true)];
        let (notes, signals) = babel_fitness_notes(&conn, &ledger, now);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].verdict, "flag");
        assert_eq!(signals.len(), 1);
        assert!(matches!(
            &signals[0],
            CollectorSignal::Escalate { reason } if reason.contains("skill-bad")
        ));
    }

    #[test]
    fn babel_fitness_notes_skip_unaccepted_unripe_and_unobservable() {
        let now = 1_800_100_000i64;
        let ripe = now - BABEL_FITNESS_HORIZON_SECS - 100;
        let conn = babel_fitness_db(ripe, 1.0, 0.5);
        let ledger = vec![
            improve_record("rejected", ripe, false),     // not accepted
            improve_record("too-fresh", now - 60, true), // horizon not observable
            improve_record("ancient", now - 30 * 86_400, true), // aged out
        ];
        let (notes, signals) = babel_fitness_notes(&conn, &ledger, now);
        assert!(notes.is_empty(), "nothing assessable in this ledger");
        assert!(signals.is_empty());
    }

    // ── config defaults ──────────────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = SelfImprovementCollectorConfig::default();
        assert!(!cfg.enabled, "disabled by default");
        assert_eq!(
            cfg.interval_secs,
            crate::config::automation::DEFAULT_SELF_IMPROVEMENT_COLLECTOR_INTERVAL_SECS
        );
        assert_eq!(
            cfg.interval_duration(),
            std::time::Duration::from_secs(
                crate::config::automation::DEFAULT_SELF_IMPROVEMENT_COLLECTOR_INTERVAL_SECS
            )
        );
        assert_eq!(cfg.window_days, 30);
        assert_eq!(cfg.min_freq_threshold, 3);
    }

    #[test]
    fn interval_floor_clamps_zero() {
        let cfg = SelfImprovementCollectorConfig {
            interval_secs: 0,
            ..Default::default()
        };
        assert_eq!(cfg.interval_duration(), std::time::Duration::from_secs(60));
    }

    // ── spawn disabled → None ────────────────────────────────────────────────

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let cfg = SelfImprovementCollectorConfig {
            enabled: false,
            ..Default::default()
        };
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_self_improvement_collector_loop(
            cfg,
            "/nonexistent".into(),
            "/nonexistent".into(),
            writer.clone(),
        );
        assert!(handle.is_none(), "disabled config must return None");
        drop(writer);
        join.await.ok();
    }

    // ── tick on empty DB emits WAL frames and zero signals ───────────────────

    #[tokio::test]
    async fn tick_on_empty_db_emits_wal_frames_and_zero_signals() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let home = dir.path().to_path_buf();
        // Create schema.
        drop(store::open(&db_path).unwrap());

        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let cfg = SelfImprovementCollectorConfig::default();
        let report = run_self_improvement_collector_tick(&db_path, &home, cfg, &writer)
            .await
            .unwrap();

        assert_eq!(report.signals.len(), 0);
        assert_eq!(report.topics_scanned, 0);
        assert_eq!(report.lessons_read, 0);

        drop(writer);
        join.await.ok();

        // Verify both WAL frames landed.
        let bytes = std::fs::read(&seg).unwrap();
        assert!(
            bytes.windows(1).any(|w| w[0] == 0xBE),
            "0xBE STARTED must be in WAL"
        );
        assert!(
            bytes.windows(1).any(|w| w[0] == 0xBF),
            "0xBF DONE must be in WAL"
        );
    }

    #[tokio::test]
    async fn nightly_tick_distills_cross_session_pattern_and_audits_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        drop(store::open(&db_path).unwrap());
        let trajectories = dir.path().join("trajectories");
        std::fs::create_dir_all(&trajectories).unwrap();
        for index in 0..5 {
            let record = crate::mcp::harness::TurnRecord {
                turn: 1,
                prompt_hash: format!("session-{index}"),
                prompt_len: 10,
                tool_calls: vec!["filesystem/read".into(), "editor/apply".into()],
                verdict: "tool_calls".into(),
                ts_unix: 1_700_000_000 + index,
            };
            std::fs::write(
                trajectories.join(format!("session-{index}.jsonl")),
                format!("{}\n", serde_json::to_string(&record).unwrap()),
            )
            .unwrap();
        }

        let segment = dir.path().join("distill.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let cfg = SelfImprovementCollectorConfig {
            propose_skills: true,
            ..Default::default()
        };
        let report = run_self_improvement_collector_tick(&db_path, dir.path(), cfg, &writer)
            .await
            .unwrap();
        assert_eq!(report.distill_candidates, 1);
        assert_eq!(report.distill_proposals_staged, 1);
        assert_eq!(
            std::fs::read_dir(dir.path().join("proposals"))
                .unwrap()
                .map(|entry| entry.expect("read proposal directory entry"))
                .filter(|entry| { entry.path().extension() == Some(std::ffi::OsStr::new("json")) })
                .count(),
            1
        );

        drop(writer);
        join.await.unwrap();
        let bytes = std::fs::read(segment).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = segment_header.header_len();
        let mut candidate_payload = None;
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if frame.header.event_type == EVENT_TYPE_EXTENDED
                && frame.header.event_subtype == ExtendedSubtype::SkillDistillCandidate as u8
            {
                candidate_payload =
                    Some(serde_json::from_slice::<serde_json::Value>(frame.payload).unwrap());
            }
            cursor += frame.header.total_len as usize;
        }
        let payload = candidate_payload.expect("candidate WAL frame must be present");
        assert_eq!(payload["supporting_sessions"], 5);
        assert_eq!(payload["eligible_sessions"], 5);
        assert_eq!(payload["confidence_milli"], 1000);
        assert_eq!(payload["proposal_staged"], true);
        assert_eq!(
            payload["sequence_hash_sha256"]
                .as_str()
                .expect("hash string")
                .len(),
            64
        );
    }

    // ── spawn enabled → Some, aborts cleanly ────────────────────────────────

    #[tokio::test]
    async fn spawn_returns_some_when_enabled_and_aborts_cleanly() {
        let cfg = SelfImprovementCollectorConfig {
            enabled: true,
            interval_secs: 999_999,
            ..Default::default()
        };
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_self_improvement_collector_loop(
            cfg,
            "/nonexistent".into(),
            "/nonexistent".into(),
            writer.clone(),
        )
        .expect("enabled config must return Some");
        handle.abort();
        let _ = handle.await;
        drop(writer);
        join.await.ok();
    }

    // ── is_verified_deployed ────────────────────────────────────────────────

    fn write_installed_artifact(skills_root: &Path, skill_id: &str) {
        let skill_dir = skills_root.join(skill_id);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("skill.yaml"), b"enabled: true").unwrap();
    }

    /// PR5-050: the two callers read the SAME evidence with opposite risk. The
    /// collector escalates on `false`; the evolver does more work on `false`. So
    /// an unprovable state must answer differently to each — absence is the only
    /// thing that lets the evolver proceed.
    #[test]
    fn possibly_deployed_and_verified_deployed_agree_except_on_the_unknown() {
        // Absence: both say "not deployed" — the evolver may stage.
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_verified_deployed(dir.path(), "ghost", 0));
        assert!(!is_possibly_deployed(dir.path(), "ghost", 0));

        // A present, settled artifact: both say deployed.
        let skills = dir.path().join("skills");
        write_installed_artifact(&skills, "my_skill");
        assert!(is_verified_deployed(&skills, "my_skill", 0));
        assert!(is_possibly_deployed(&skills, "my_skill", 0));

        // The unknown arm is what the two disagree on, pinned on the pure
        // helper because a filesystem without mtime is not summonable in a test:
        // no mtime means "not settled" (collector escalates) while
        // `is_possibly_deployed` maps the same input to "deployed" (evolver
        // skips) — see its `None => true` arm.
        assert!(!is_deployment_settled(
            None,
            std::time::SystemTime::now(),
            std::time::Duration::from_secs(0)
        ));
    }

    #[test]
    fn is_verified_deployed_missing_returns_false() {
        // Every absence arm fails closed — read through the capability-bound
        // store: absent skills root, absent skill dir under a present root, and a
        // present skill dir with no `skill.yaml` artifact.
        assert!(!is_verified_deployed(
            Path::new("/nonexistent/skills"),
            "ghost",
            0
        ));
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_verified_deployed(dir.path(), "ghost", 0));

        // Skill dir exists but the artifact does not → open_regular_file errs.
        let skills = dir.path().join("skills");
        std::fs::create_dir_all(skills.join("my_skill")).unwrap();
        assert!(!is_verified_deployed(&skills, "my_skill", 0));
    }

    #[test]
    fn is_verified_deployed_existing_artifact_zero_age_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let skills = dir.path().join("skills");
        write_installed_artifact(&skills, "my_skill");
        // min_age_secs = 0 → elapsed always >= 0.
        assert!(is_verified_deployed(&skills, "my_skill", 0));
    }

    #[test]
    fn is_verified_deployed_fresh_artifact_fails_age_check() {
        let dir = tempfile::tempdir().unwrap();
        let skills = dir.path().join("skills");
        write_installed_artifact(&skills, "my_skill");
        // A just-written artifact won't have elapsed 999_999 seconds.
        assert!(!is_verified_deployed(&skills, "my_skill", 999_999));
    }

    // ── is_deployment_settled — pure branch coverage (GOLD-R3-11) ────────────

    #[test]
    fn deployment_settled_missing_mtime_fails_closed() {
        // Platform reports no mtime → cannot prove settled → NOT deployed.
        assert!(!is_deployment_settled(
            None,
            std::time::SystemTime::UNIX_EPOCH,
            std::time::Duration::ZERO,
        ));
    }

    #[test]
    fn deployment_settled_old_enough_is_deployed() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10_000);
        let modified = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        // 9_000s old, min_age 60s → settled.
        assert!(is_deployment_settled(
            Some(modified),
            now,
            std::time::Duration::from_secs(60),
        ));
    }

    #[test]
    fn deployment_settled_too_young_is_not_deployed() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_005);
        let modified = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        // 5s old, min_age 60s → not yet settled.
        assert!(!is_deployment_settled(
            Some(modified),
            now,
            std::time::Duration::from_secs(60),
        ));
    }

    #[test]
    fn deployment_settled_future_mtime_fails_closed() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let modified = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000);
        // mtime in the future (clock skew / just touched) → NOT settled.
        assert!(!is_deployment_settled(
            Some(modified),
            now,
            std::time::Duration::ZERO,
        ));
    }

    #[test]
    fn deployment_settled_exact_min_age_boundary_is_deployed() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_060);
        let modified = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        // Exactly min_age (60s) old → `elapsed >= min_age` is inclusive.
        assert!(is_deployment_settled(
            Some(modified),
            now,
            std::time::Duration::from_secs(60),
        ));
    }

    // ── sidecar written on tick ──────────────────────────────────────────────

    #[tokio::test]
    async fn tick_writes_sidecar_json() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let home = dir.path().to_path_buf();
        drop(store::open(&db_path).unwrap());

        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();

        let cfg = SelfImprovementCollectorConfig::default();
        let _report = run_self_improvement_collector_tick(&db_path, &home, cfg, &writer)
            .await
            .unwrap();

        drop(writer);
        join.await.ok();

        let sidecar = home.join("self_improvement_signals.json");
        assert!(sidecar.exists(), "sidecar JSON must be written");
        let parsed: CollectorReport =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(parsed.signals.len(), 0);
    }
}
