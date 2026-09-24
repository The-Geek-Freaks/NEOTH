//! Round-3 v0.4 G-02 cron — daily-tick daemon loop that scans
//! `idx_profile` for novel high-confidence claims + enqueues each
//! as a `ProactiveItem` for the G-01 durable egress transaction.
//!
//! Glue between:
//! - `profile::surfacing::find_novel_high_confidence_claims` —
//!   pure-fn finder.
//! - `profile::surfacing::build_g02_proactive_item` — render
//!   bilingual ProactiveItem.
//! - `proactive::ProactiveQueue::enqueue` — bounded queue + dedup.
//! - `daemon::proactive_dispatcher` — WAL-bound transport and private history.
//!
//! Daily cadence matches the novelty window default — running
//! more frequently is wasteful (same claims surface; dedup key
//! catches the re-enqueue but it's a load on the queue's load+save
//! cycle). Operators tune via
//! `freedom.yaml::profile.g02_cron_interval_secs` in the follow-on.

use std::path::PathBuf;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Daily cadence — 24h in seconds. Per-claim dedup means more
/// frequent ticks just re-process the same set; no harm but no
/// gain.
pub const G02_CRON_INTERVAL_SECS: u64 = 24 * 3600;

/// Per-tick cap on claims enqueued. Caps the operator-visible
/// notification storm if a fresh extraction pass lands many
/// high-confidence claims at once.
pub const G02_PER_TICK_CAP: usize = 5;

/// Default channel for G-02 ProactiveItems. Operators see them in
/// the JSONL sidecar regardless of channel; the channel field gets
/// honoured once channel adapters consume the sidecar.
pub const G02_DEFAULT_CHANNEL: &str = "cli";

/// One G-02 tick: find novel claims in views.db, render each as a
/// ProactiveItem, enqueue into proactive_queue.json. Returns the
/// number of newly-enqueued items (dedup may reject some).
/// Pure-fn (no async) for testability.
pub fn run_g02_surfacing_tick(home: &std::path::Path, now_unix: i64) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;
    use crate::profile::surfacing::{
        DEFAULT_HIGH_CONFIDENCE_THRESHOLD, DEFAULT_NOVELTY_WINDOW_SECS, build_g02_proactive_item,
        find_novel_high_confidence_claims,
    };

    // ADOPT31-D6: the specialist advisor is advisory-only and shares this
    // existing daily durable-proactive seam. It consumes the already-defined
    // usage projection; provider completion is never promoted to correctness.
    let advisor_enqueued = match run_specialist_advisor_tick(home, now_unix) {
        Ok(enqueued) => enqueued,
        Err(error) => {
            // D6 input must fail closed without suppressing this producer's
            // independent profile-claim surface.
            warn!(error = %error, "specialist advisor tick suppressed");
            0
        }
    };

    let views_path = home.join("views.db");
    if !views_path.exists() {
        // Fresh install — no profile yet. Quiet no-op so the cron
        // doesn't spam the log during the wizard's first week.
        return Ok(advisor_enqueued);
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let since_unix = now_unix.saturating_sub(DEFAULT_NOVELTY_WINDOW_SECS as i64);
    let claims = find_novel_high_confidence_claims(
        &conn,
        since_unix,
        DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
        G02_PER_TICK_CAP,
    )
    .map_err(|e| format!("find_novel_high_confidence_claims failed: {e}"))?;
    if claims.is_empty() {
        return Ok(advisor_enqueued);
    }

    let items = claims
        .iter()
        .map(|claim| build_g02_proactive_item(claim, G02_DEFAULT_CHANNEL, now_unix))
        .collect::<Vec<_>>();
    for item in &items {
        item.validate()
            .map_err(|error| format!("invalid G-02 proactive item: {error}"))?;
    }

    let queue_path = home.join("proactive_queue.json");
    ProactiveQueue::modify(&queue_path, |queue| {
        let result = items.into_iter().try_fold(0usize, |count, item| {
            queue
                .enqueue(item)
                .map(|inserted| count + usize::from(inserted))
        });
        // Always persist on success — same as the old unconditional save_to call.
        (result.is_ok(), result)
    })
    .map_err(|e| format!("queue load/save failed: {e}"))?
    .map_err(|e| format!("G-02 proactive enqueue rejected: {e:#}"))
    .map(|enqueued| advisor_enqueued + enqueued)
}

/// ADOPT31-D6's daily consumer: project the last 30 days of local usage into
/// bounded candidate or assessment request. The explicit operator evidence
/// file is strict and local; invalid input returns an error to the caller,
/// which isolates it from the independent G-02 profile-claim work.
fn run_specialist_advisor_tick(home: &std::path::Path, now_unix: i64) -> Result<usize, String> {
    use crate::analytics::specialist_advisor::{
        DEFAULT_MINIMUM_CALL_COUNT, analyze, load_operator_assessments, proactive_items,
    };
    use crate::daemon::usage_log::aggregate;
    use crate::proactive::ProactiveQueue;

    const ADVISOR_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
    let since_unix = now_unix.saturating_sub(ADVISOR_WINDOW_SECS);
    let rollup = aggregate(home, since_unix, now_unix);
    let assessments = match load_operator_assessments(home) {
        Ok(assessments) => assessments,
        Err(error) => {
            let queue_path = home.join("proactive_queue.json");
            let _ = ProactiveQueue::modify(&queue_path, |queue| {
                let result =
                    queue.reconcile_specialist_advisor(now_unix, ADVISOR_WINDOW_SECS, Vec::new());
                (result.is_ok(), result)
            });
            return Err(error);
        }
    };
    let report = analyze(&rollup, DEFAULT_MINIMUM_CALL_COUNT, &assessments);
    let items = proactive_items(&report, now_unix);
    let queue_path = home.join("proactive_queue.json");
    ProactiveQueue::modify(&queue_path, |queue| {
        let result = queue.reconcile_specialist_advisor(now_unix, ADVISOR_WINDOW_SECS, items);
        (result.is_ok(), result)
    })
    .map_err(|error| format!("specialist-advisor queue load/save failed: {error}"))?
    .map_err(|error| format!("specialist-advisor proactive enqueue rejected: {error:#}"))
}

/// Spawn the daemon-side G-02 cron loop. Matches the doctor_cron /
/// reflection_cron / proactive_dispatcher pattern.
pub fn spawn_g02_surfacing_cron_loop(home: PathBuf, interval_secs: u64) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(60));
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            home = %home.display(),
            "G-02 surfacing cron loop spawned"
        );
        // GOLD-ADAPT-ODY-07b — register this daemon-lifetime loop as a background
        // job so `neoth jobs list` + the ODY-07 bg_monitor see it as Running. No
        // `.exit` marker is ever written (the loop runs for the daemon's lifetime),
        // which is the accurate status. No-op before `init_global_registry` (chat).
        if let Some(reg) = crate::daemon::bg_jobs::global_registry() {
            let ts = crate::time::now_unix_secs();
            reg.register(
                crate::daemon::bg_jobs::BgJobId::new("g02-surfacing-cron", ts),
                "G-02 profile-claim surfacing loop",
                ts,
                None,
            )
            .await;
        }
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now_unix = crate::time::utc_now().timestamp();
            match run_g02_surfacing_tick(&home, now_unix) {
                Ok(0) => tracing::debug!("G-02 surfacing tick: no novel claims"),
                Ok(n) => info!(
                    enqueued = n,
                    "G-02 surfacing tick: {n} novel claim(s) enqueued for drain",
                ),
                Err(e) => warn!(error = %e, "G-02 surfacing tick failed; will retry next interval"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::usage_log::{UsageEvent, append};
    use tempfile::TempDir;

    #[test]
    fn g02_tick_no_views_db_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let n = run_g02_surfacing_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn g02_tick_empty_profile_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let views_path = tmp.path().join("views.db");
        let _conn = crate::memory::store::open(&views_path).unwrap();
        let n = run_g02_surfacing_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn g02_constants_canonical() {
        assert_eq!(G02_CRON_INTERVAL_SECS, 24 * 3600);
        assert_eq!(G02_PER_TICK_CAP, 5);
        assert_eq!(G02_DEFAULT_CHANNEL, "cli");
    }

    #[test]
    fn g02_tick_surfaces_a_fully_attested_specialist_candidate_from_local_usage() {
        let home = TempDir::new().unwrap();
        let now = 1_700_000_000;
        for _ in 0..100 {
            append(
                home.path(),
                &UsageEvent {
                    ts_unix: now - 1,
                    provider: "local_qwen".to_string(),
                    model: "qwen".to_string(),
                    cost_usd: Some(0.0),
                    latency_ms: 1,
                    ok: true,
                    call_scope: Some("chat_provider_round".to_string()),
                    source: Some("chat".to_string()),
                    call_type: Some("chat_provider_round".to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        std::fs::write(
            home.path().join("specialist_assessments.json"),
            r#"{
                "schema_version": 1,
                "assessments": [{
                    "workflow": "chat_turn",
                    "outcome_checkable": "confirmed",
                    "expert_agreement": "confirmed",
                    "model_succeeds_sometimes": "confirmed",
                    "not_lucky_guess": "confirmed",
                    "multi_step_committed": "confirmed",
                    "owns_tools_and_schemas": "confirmed",
                    "asymmetric_error_costs": "confirmed",
                    "data_stays_local": "confirmed"
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(run_g02_surfacing_tick(home.path(), now).unwrap(), 1);
        let queue =
            crate::proactive::ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap();
        assert_eq!(queue.len(), 1);
        let queue_json = std::fs::read_to_string(home.path().join("proactive_queue.json")).unwrap();
        assert!(queue_json.contains("specialist-advisor:candidate:chat_turn"));
        let mut queue =
            crate::proactive::ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap();
        assert_eq!(queue.drain(now, 1).len(), 1);
        queue
            .save_to(&home.path().join("proactive_queue.json"))
            .unwrap();
        assert_eq!(
            run_g02_surfacing_tick(home.path(), now + 86_400).unwrap(),
            0
        );
        for _ in 0..100 {
            append(
                home.path(),
                &UsageEvent {
                    ts_unix: now + 30 * 24 * 60 * 60 - 1,
                    provider: "local_qwen".to_string(),
                    model: "qwen".to_string(),
                    cost_usd: Some(0.0),
                    latency_ms: 1,
                    ok: true,
                    call_scope: Some("chat_provider_round".to_string()),
                    source: Some("chat".to_string()),
                    call_type: Some("chat_provider_round".to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        assert_eq!(
            run_g02_surfacing_tick(home.path(), now + 30 * 24 * 60 * 60).unwrap(),
            1
        );
    }

    #[test]
    fn invalid_specialist_assessment_suppresses_only_d6_output() {
        let home = TempDir::new().unwrap();
        let queue_path = home.path().join("proactive_queue.json");
        crate::proactive::ProactiveQueue::enqueue_at(
            &queue_path,
            crate::proactive::ProactiveItem {
                priority: 60,
                dedup_key: "g02_surfacing:independent-fixture".to_string(),
                channel: "cli".to_string(),
                account_id: None,
                account_binding: None,
                source: "g02_surfacing".to_string(),
                body: "independent profile-surfacing fixture".to_string(),
                scheduled_for_unix: 0,
                is_failure: false,
                expires_unix: 0,
            },
        )
        .unwrap();
        std::fs::write(home.path().join("specialist_assessments.json"), "not json").unwrap();
        assert_eq!(
            run_g02_surfacing_tick(home.path(), 1_700_000_000).unwrap(),
            0
        );
        let queue = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek()[0].source, "g02_surfacing");
        assert!(
            !queue
                .peek()
                .iter()
                .any(|item| item.source == "specialist_advisor")
        );
    }
}
