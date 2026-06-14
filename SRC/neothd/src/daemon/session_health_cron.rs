//! GOLD-ADAPT-VIEW-05 — session-health / outcome daemon cron.
//!
//! Adapts agentsview's session health/outcome signal to NEOTH's substrate: an
//! A–F health grade for the most-recent active day, derived from the WAL audit
//! trail, alerting when the grade degrades. Mirrors [`super::token_anomaly_cron`]
//! (a pure-ish [`run_session_health_tick`] + a [`spawn_session_health_cron_loop`]
//! that returns `None` when disabled).
//!
//! ## Substrate: the WAL itself (no new persistence, no session_id needed)
//!
//! NEOTH does not tag WAL frames with a chat session id (it is computed inside
//! `cli/chat.rs`, after several emit sites), so a strict per-conversation grade
//! is not derivable from the audit trail. Instead — exactly like
//! `token_anomaly_cron` — this grades the most-recent UTC DAY of activity (a
//! rolling "recent health" window), which IS fully derivable from the frames'
//! HLC wall-clock. The signals, counted per day:
//!
//! - **activity** = `0x21 PROVIDER_RESPONSE` frames (the denominator),
//! - **refusal-failures** = `0x1A REFUSAL_PERSISTENT` + `0x27
//!   REFUSAL_ABLITERATED_FAILED` (the operator got blocked AFTER recovery was
//!   exhausted) — note `0x28 REFUSAL_HARD_BLOCKED` + `0x26 ABLITERATED_USED` are
//!   the moral-core / fallback working CORRECTLY and are NOT counted as bad
//!   health,
//! - **job-failures** = `0x42 JOB_FAILED`,
//! - **context-pressure** = mean input tokens per reply (from `0x21`).
//!
//! A `0x6F SESSION_HEALTH_DEGRADED` frame is emitted ONLY when the most-recent
//! day has at least `min_activity` replies AND its grade is at or below
//! `alert_at_or_below` (default `D`), so the event is an actionable degradation
//! signal, not per-tick "still healthy" noise. Counts + a grade are not secrets,
//! so the payload is recorded in the clear.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::SessionHealthConfig;
use crate::wal::writer::WalWriterHandle;

const SECS_PER_DAY: u64 = 86_400;

/// A health grade for one day's activity. Ordered worst→best so
/// `grade <= Grade::D` means "degraded" (D or F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    F,
    D,
    C,
    B,
    A,
}

impl Grade {
    /// Map a 0–100 health score to a letter grade.
    fn from_score(score: f64) -> Grade {
        if score >= 90.0 {
            Grade::A
        } else if score >= 75.0 {
            Grade::B
        } else if score >= 60.0 {
            Grade::C
        } else if score >= 45.0 {
            Grade::D
        } else {
            Grade::F
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }

    /// Parse a config letter (`A`..`F`, case-insensitive). Unknown → `D`.
    pub fn parse_or_d(s: &str) -> Grade {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Grade::A,
            "B" => Grade::B,
            "C" => Grade::C,
            "F" => Grade::F,
            _ => Grade::D,
        }
    }
}

/// Per-UTC-day health rollup derived from the WAL frames.
#[derive(Default, Debug, Clone)]
struct DayHealth {
    /// `0x21 PROVIDER_RESPONSE` count — the activity denominator.
    activity: u64,
    /// `0x1A` + `0x27` — refusals the operator hit after recovery was exhausted.
    refusal_failures: u64,
    /// `0x42 JOB_FAILED`.
    job_failures: u64,
    /// Sum of `0x21` input tokens (context-pressure numerator).
    input_tokens: u64,
}

/// Minimal `0x21` payload read (input tokens only). `serde(default)`-tolerant.
#[derive(Deserialize)]
struct ProviderResponsePayload {
    #[serde(default)]
    input_tokens: u64,
}

/// A degraded-health alert — returned by the tick + the shape of the `0x6F`
/// payload.
#[derive(Debug, Clone)]
pub struct SessionHealthAlert {
    pub grade: Grade,
    pub score: f64,
    pub day_unix: u64,
    pub activity: u64,
    pub refusal_failures: u64,
    pub job_failures: u64,
    pub refusal_rate: f64,
    pub failure_rate: f64,
    pub mean_input_tokens: u64,
}

/// Health score 0–100 for a day. Starts at 100; refusal-failures and
/// job-failures demote it (a failure costs more than a refusal); very high
/// mean context applies a small penalty.
fn day_score(d: &DayHealth) -> (f64, f64, f64, u64) {
    let act = d.activity.max(1) as f64;
    let refusal_rate = d.refusal_failures as f64 / act;
    let failure_rate = d.job_failures as f64 / (d.activity + d.job_failures).max(1) as f64;
    let mean_input = d.input_tokens / d.activity.max(1);
    let mut score = 100.0;
    score -= refusal_rate * 150.0;
    score -= failure_rate * 200.0;
    if mean_input as f64 > 100_000.0 {
        score -= 5.0;
    }
    (score.clamp(0.0, 100.0), refusal_rate, failure_rate, mean_input)
}

/// Scan every `*.wal` segment, bucketing the health-signal frames by UTC
/// calendar day. Unreadable segments / undecodable frames are skipped, never
/// fatal (a torn tail must not blind the monitor).
fn scan_health_by_day(wal_dir: &Path) -> BTreeMap<u64, DayHealth> {
    use crate::wal::events::{
        EVENT_TYPE_JOB_FAILED, EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_REFUSAL_ABLITERATED_FAILED,
        EVENT_TYPE_REFUSAL_PERSISTENT,
    };
    let mut by_day: BTreeMap<u64, DayHealth> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(wal_dir) else {
        return by_day;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wal") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            continue;
        };
        let mut cursor = hdr.header_len();
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            let day = dec.header.hlc.physical_ns() / 1_000_000_000 / SECS_PER_DAY;
            let ty = dec.header.event_type;
            if ty == EVENT_TYPE_PROVIDER_RESPONSE {
                let e = by_day.entry(day).or_default();
                e.activity = e.activity.saturating_add(1);
                if let Ok(p) = serde_json::from_slice::<ProviderResponsePayload>(dec.payload) {
                    e.input_tokens = e.input_tokens.saturating_add(p.input_tokens);
                }
            } else if ty == EVENT_TYPE_REFUSAL_PERSISTENT
                || ty == EVENT_TYPE_REFUSAL_ABLITERATED_FAILED
            {
                let e = by_day.entry(day).or_default();
                e.refusal_failures = e.refusal_failures.saturating_add(1);
            } else if ty == EVENT_TYPE_JOB_FAILED {
                let e = by_day.entry(day).or_default();
                e.job_failures = e.job_failures.saturating_add(1);
            }
            cursor += total;
        }
    }
    by_day
}

/// Grade the most-recent day with at least `min_activity` replies; return an
/// alert when its grade is at or below `alert_at_or_below`. `None` otherwise.
fn evaluate_health(
    by_day: &BTreeMap<u64, DayHealth>,
    config: &SessionHealthConfig,
) -> Option<SessionHealthAlert> {
    let (day_unix, day) = by_day.iter().next_back()?;
    if day.activity < config.min_activity {
        return None;
    }
    let (score, refusal_rate, failure_rate, mean_input_tokens) = day_score(day);
    let grade = Grade::from_score(score);
    let threshold = Grade::parse_or_d(&config.alert_at_or_below);
    if grade > threshold {
        return None;
    }
    Some(SessionHealthAlert {
        grade,
        score,
        day_unix: *day_unix * SECS_PER_DAY,
        activity: day.activity,
        refusal_failures: day.refusal_failures,
        job_failures: day.job_failures,
        refusal_rate,
        failure_rate,
        mean_input_tokens,
    })
}

async fn emit_alert(writer: &WalWriterHandle, alert: &SessionHealthAlert) -> Result<(), String> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "grade": alert.grade.as_str(),
        "score": alert.score,
        "day_unix": alert.day_unix,
        "activity": alert.activity,
        "refusal_failures": alert.refusal_failures,
        "job_failures": alert.job_failures,
        "refusal_rate": alert.refusal_rate,
        "failure_rate": alert.failure_rate,
        "mean_input_tokens": alert.mean_input_tokens,
    }))
    .map_err(|e| format!("serialize session-health payload: {e}"))?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_SESSION_HEALTH_DEGRADED,
        &payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    writer
        .append(header, payload)
        .await
        .map_err(|e| format!("wal append: {e}"))?;
    Ok(())
}

/// One session-health cron pass: scan the WAL → grade the recent day → on a
/// degraded grade emit `0x6F` and return `Ok(Some(alert))`. `Ok(None)` when the
/// recent day is healthy or below the activity floor. `wal_dir` is the daemon
/// WAL dir (`home/wal`).
pub async fn run_session_health_tick(
    wal_dir: &Path,
    config: &SessionHealthConfig,
    writer: &WalWriterHandle,
) -> Result<Option<SessionHealthAlert>, String> {
    let by_day = scan_health_by_day(wal_dir);
    let Some(alert) = evaluate_health(&by_day, config) else {
        return Ok(None);
    };
    emit_alert(writer, &alert).await?;
    tracing::warn!(
        grade = alert.grade.as_str(),
        score = alert.score,
        activity = alert.activity,
        refusal_failures = alert.refusal_failures,
        job_failures = alert.job_failures,
        "session-health degraded: the recent activity window graded {} — a spike in \
         refusal-failures or job-failures looks like this. Review \
         `neoth wal show --type session_health_degraded`",
        alert.grade.as_str(),
    );
    Ok(Some(alert))
}

/// Spawn the session-health cron loop. Returns the `JoinHandle` so the daemon
/// tracks it; `None` when `config.enabled == false` (the default) so opt-out
/// operators carry no idle task. Interval is clamped to a 60s floor by
/// [`SessionHealthConfig::interval_duration`].
pub fn spawn_session_health_cron_loop(
    config: SessionHealthConfig,
    wal_dir: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("session-health cron disabled in config (session_health.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            alert_at_or_below = %config.alert_at_or_below,
            "session-health cron loop online (GOLD-ADAPT-VIEW-05)",
        );
        loop {
            ticker.tick().await;
            match run_session_health_tick(&wal_dir, &config, &writer).await {
                Ok(Some(alert)) => tracing::info!(
                    grade = alert.grade.as_str(),
                    "session-health cron: 0x6F emitted",
                ),
                Ok(None) => tracing::debug!("session-health cron: healthy this tick"),
                Err(e) => tracing::error!(error = %e, "session-health tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(min_activity: u64, alert: &str) -> SessionHealthConfig {
        SessionHealthConfig {
            enabled: true,
            interval_secs: 3600,
            min_activity,
            alert_at_or_below: alert.to_string(),
        }
    }

    #[test]
    fn grade_orders_worst_to_best() {
        assert!(Grade::F < Grade::D);
        assert!(Grade::D < Grade::C);
        assert!(Grade::C < Grade::B);
        assert!(Grade::B < Grade::A);
        // "degraded" = at or below D
        assert!(Grade::D <= Grade::D);
        assert!(Grade::F <= Grade::D);
        assert!(Grade::C > Grade::D);
    }

    #[test]
    fn clean_day_grades_a() {
        let d = DayHealth {
            activity: 100,
            refusal_failures: 0,
            job_failures: 0,
            input_tokens: 100 * 2_000,
        };
        let (score, _, _, _) = day_score(&d);
        assert_eq!(Grade::from_score(score), Grade::A);
    }

    #[test]
    fn high_refusal_and_failure_grades_f() {
        let d = DayHealth {
            activity: 100,
            refusal_failures: 40, // 40% refusal-failure rate
            job_failures: 30,
            input_tokens: 0,
        };
        let (score, refusal_rate, failure_rate, _) = day_score(&d);
        assert!((refusal_rate - 0.40).abs() < 1e-6);
        assert!(failure_rate > 0.2);
        assert_eq!(Grade::from_score(score), Grade::F, "score was {score}");
    }

    #[test]
    fn evaluate_skips_below_min_activity() {
        let mut by_day = BTreeMap::new();
        by_day.insert(
            100,
            DayHealth {
                activity: 3, // below the floor
                refusal_failures: 3,
                job_failures: 3,
                input_tokens: 0,
            },
        );
        // Even though this day is awful, too little activity → no grade/alert.
        assert!(evaluate_health(&by_day, &cfg(10, "D")).is_none());
    }

    #[test]
    fn evaluate_alerts_on_degraded_recent_day_only() {
        let mut by_day = BTreeMap::new();
        // An older healthy day...
        by_day.insert(
            100,
            DayHealth {
                activity: 50,
                refusal_failures: 0,
                job_failures: 0,
                input_tokens: 0,
            },
        );
        // ...and a recent degraded day (the one graded).
        by_day.insert(
            101,
            DayHealth {
                activity: 50,
                refusal_failures: 25,
                job_failures: 10,
                input_tokens: 0,
            },
        );
        let alert = evaluate_health(&by_day, &cfg(10, "D")).expect("recent day is degraded");
        assert!(alert.grade <= Grade::D);
        assert_eq!(alert.day_unix, 101 * SECS_PER_DAY);
        assert_eq!(alert.activity, 50);
    }

    #[test]
    fn evaluate_quiet_when_recent_day_healthy() {
        let mut by_day = BTreeMap::new();
        by_day.insert(
            200,
            DayHealth {
                activity: 80,
                refusal_failures: 1,
                job_failures: 0,
                input_tokens: 80 * 1_000,
            },
        );
        assert!(evaluate_health(&by_day, &cfg(10, "D")).is_none());
    }

    #[tokio::test]
    async fn tick_scans_multi_type_frames_and_emits_0x6f_on_a_degraded_day() {
        use crate::wal::events::{
            EVENT_TYPE_JOB_FAILED, EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_REFUSAL_PERSISTENT,
            EVENT_TYPE_SESSION_HEALTH_DEGRADED,
        };

        async fn append(writer: &WalWriterHandle, ty: u8, payload: serde_json::Value) {
            let p = serde_json::to_vec(&payload).unwrap();
            let h = crate::wal::HeaderBuilder::new(ty, &p).build();
            writer.append(h, p).await.unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let (writer, join) = crate::wal::writer::spawn(dir.path().join("000001.wal")).unwrap();
        // 12 replies (activity ≥ min), 8 refusal-failures, 5 job-failures → F.
        // Two NON-counted frames (hard-block + abliterated-used) prove they are
        // excluded from the bad-health tally (the moral core working correctly).
        for _ in 0..12 {
            append(&writer, EVENT_TYPE_PROVIDER_RESPONSE, serde_json::json!({"input_tokens": 1000}))
                .await;
        }
        for _ in 0..8 {
            append(&writer, EVENT_TYPE_REFUSAL_PERSISTENT, serde_json::json!({})).await;
        }
        for _ in 0..5 {
            append(&writer, EVENT_TYPE_JOB_FAILED, serde_json::json!({})).await;
        }
        append(&writer, crate::wal::events::EVENT_TYPE_REFUSAL_HARD_BLOCKED, serde_json::json!({}))
            .await;
        append(&writer, crate::wal::events::EVENT_TYPE_REFUSAL_ABLITERATED_USED, serde_json::json!({}))
            .await;
        drop(writer);
        let _ = join.await;

        // A live writer for the tick's own 0x6F emit (separate segment).
        let (writer2, join2) = crate::wal::writer::spawn(dir.path().join("000002.wal")).unwrap();
        let alert = run_session_health_tick(dir.path(), &cfg(10, "D"), &writer2)
            .await
            .unwrap()
            .expect("a 67%-refusal-failure day must alert");
        assert!(alert.grade <= Grade::D, "grade was {}", alert.grade.as_str());
        assert_eq!(alert.activity, 12);
        assert_eq!(alert.refusal_failures, 8, "hard-block + abliterated-used must NOT count");
        assert_eq!(alert.job_failures, 5);
        drop(writer2);
        let _ = join2.await;

        // The 0x6F frame landed + decodes with the grade in its payload.
        let bytes = std::fs::read(dir.path().join("000002.wal")).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let dec = crate::wal::frame::decode_frame(&bytes[hdr.header_len()..]).unwrap();
        assert_eq!(dec.header.event_type, EVENT_TYPE_SESSION_HEALTH_DEGRADED);
        let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
        assert_eq!(v["activity"], 12);
        assert_eq!(v["grade"], alert.grade.as_str());
    }
}
