//! GOLD-ADAPT-JV-PRO-02 — token-anomaly security tripwire daemon cron.
//!
//! Adapts Jarvis `token_anomaly.py:186-230`: a rolling baseline of daily LLM
//! token usage, alerting when the most-recent active day shows
//!   1. a **σ spike** — total > `mean + sigma_multiplier × stddev` of the
//!      baseline days,
//!   2. an **absolute jump** — total exceeds the baseline max by more than
//!      `abs_jump_tokens` (default 1,000,000), or
//!   3. a **new model** — a model id appears that was absent across the whole
//!      baseline window.
//! Any of these can mean a leaked provider key burning tokens, a runaway agent
//! loop, or an unexpected model route — all operator-actionable security
//! signals.
//!
//! ## Substrate: the WAL itself (no new persistence)
//!
//! NEOTH already persists every LLM reply as a `0x21 PROVIDER_RESPONSE` frame
//! carrying `{model, input_tokens, output_tokens}`, timestamped by the frame
//! header's HLC wall-clock. This cron scans the WAL segment dir, buckets those
//! frames by UTC calendar day, and runs the tripwire over the daily totals —
//! stateless, using the existing audit trail as the source of truth (no extra
//! file, no schema).
//!
//! Mirrors [`super::drift_alert_cron`]: a pure-ish [`run_token_anomaly_tick`]
//! (unit-testable against a tempdir WAL) + a [`spawn_token_anomaly_cron_loop`]
//! that returns `None` when disabled (default OFF — opt-out operators carry no
//! idle tokio task). A `0x6E TOKEN_ANOMALY_DETECTED` frame is emitted ONLY on a
//! real trip, so `neoth wal show --type token_anomaly_detected` is a clean,
//! actionable signal rather than per-tick "still fine" noise. Token COUNTS +
//! model NAMES are not secrets, so the payload is recorded in the clear (unlike
//! channel-send egress, there is no PII to hash here).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::TokenAnomalyConfig;
use crate::wal::writer::WalWriterHandle;

const SECS_PER_DAY: u64 = 86_400;

/// Per-UTC-day usage rollup derived from the WAL `0x21` frames.
#[derive(Default, Debug, Clone)]
struct DayUsage {
    tokens: u64,
    models: BTreeSet<String>,
}

/// The fields read out of a `0x21 PROVIDER_RESPONSE` payload. `serde(default)`-
/// tolerant: an older frame missing a field contributes 0 / no model rather
/// than failing the whole scan.
#[derive(Deserialize)]
struct ProviderResponsePayload {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

/// Which tripwire(s) fired — recorded in the WAL alert payload + the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Day total exceeded `mean + sigma_multiplier × stddev` of the baseline.
    SigmaSpike,
    /// Day total exceeded the baseline max by more than `abs_jump_tokens`.
    AbsoluteJump,
    /// A model used today was absent across the whole baseline window.
    NewModel(String),
}

impl AnomalyKind {
    fn tag(&self) -> &'static str {
        match self {
            AnomalyKind::SigmaSpike => "sigma_spike",
            AnomalyKind::AbsoluteJump => "absolute_jump",
            AnomalyKind::NewModel(_) => "new_model",
        }
    }
}

/// A fired tripwire with the supporting stats — returned by the tick + the
/// shape of the `0x6E` payload.
#[derive(Debug, Clone)]
pub struct TokenAnomalyAlert {
    pub kinds: Vec<AnomalyKind>,
    pub day_tokens: u64,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
    pub baseline_max: u64,
    pub baseline_days: usize,
    pub day_models: Vec<String>,
}

/// Scan every `*.wal` segment in `wal_dir`, bucketing `0x21 PROVIDER_RESPONSE`
/// token totals + model sets by UTC calendar day (derived from the frame HLC
/// wall-clock). Unreadable segments / undecodable frames are skipped, never
/// fatal — a partially-corrupt tail must not blind the tripwire.
fn scan_usage_by_day(wal_dir: &Path) -> BTreeMap<u64, DayUsage> {
    let mut by_day: BTreeMap<u64, DayUsage> = BTreeMap::new();
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
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
                && let Ok(p) = serde_json::from_slice::<ProviderResponsePayload>(dec.payload)
            {
                let day = dec.header.hlc.physical_ns() / 1_000_000_000 / SECS_PER_DAY;
                let e = by_day.entry(day).or_default();
                e.tokens = e
                    .tokens
                    .saturating_add(p.input_tokens)
                    .saturating_add(p.output_tokens);
                if let Some(m) = p.model
                    && !m.is_empty()
                {
                    e.models.insert(m);
                }
            }
            cursor = cursor.saturating_add(total);
        }
    }
    by_day
}

/// Pure tripwire over the daily buckets — the heart of the cron, unit-tested
/// directly with synthetic days. Returns `None` when there is not enough
/// baseline history, or no trigger fired. The "current" day is the most recent
/// day with usage; the baseline is the days with usage in the
/// `[current − baseline_days, current)` window.
fn evaluate_anomaly(
    by_day: &BTreeMap<u64, DayUsage>,
    config: &TokenAnomalyConfig,
) -> Option<TokenAnomalyAlert> {
    let (&test_day, test_usage) = by_day.iter().next_back()?;
    let window_lo = test_day.saturating_sub(config.baseline_days as u64);
    let baseline: Vec<&DayUsage> = by_day
        .iter()
        .filter(|(d, _)| **d < test_day && **d >= window_lo)
        .map(|(_, u)| u)
        .collect();
    if baseline.len() < config.min_baseline_days as usize {
        return None; // not enough history for a meaningful baseline
    }

    let totals: Vec<u64> = baseline.iter().map(|u| u.tokens).collect();
    let n = totals.len() as f64;
    let mean = totals.iter().sum::<u64>() as f64 / n;
    let variance = totals
        .iter()
        .map(|&t| {
            let d = t as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    let baseline_max = totals.iter().copied().max().unwrap_or(0);
    let baseline_models: BTreeSet<&String> =
        baseline.iter().flat_map(|u| u.models.iter()).collect();

    let day = test_usage.tokens;
    let mut kinds = Vec::new();

    // (1) σ spike. Guarded by `stddev > 0` (a perfectly flat baseline makes the
    //     σ test degenerate — any increase would read as "infinite σ"; the
    //     absolute-jump path covers that case) AND an absolute floor so a
    //     low-volume operator's noise can't trip it.
    if stddev > 0.0
        && (day as f64) > mean + config.sigma_multiplier * stddev
        && day >= config.min_absolute_tokens
    {
        kinds.push(AnomalyKind::SigmaSpike);
    }

    // (2) absolute jump vs the highest normal day.
    if day > baseline_max.saturating_add(config.abs_jump_tokens) {
        kinds.push(AnomalyKind::AbsoluteJump);
    }

    // (3) a model used today that no baseline day used.
    for m in &test_usage.models {
        if !baseline_models.contains(m) {
            kinds.push(AnomalyKind::NewModel(m.clone()));
        }
    }

    if kinds.is_empty() {
        return None;
    }
    Some(TokenAnomalyAlert {
        kinds,
        day_tokens: day,
        baseline_mean: mean,
        baseline_stddev: stddev,
        baseline_max,
        baseline_days: baseline.len(),
        day_models: test_usage.models.iter().cloned().collect(),
    })
}

/// Emit the `0x6E TOKEN_ANOMALY_DETECTED` WAL frame for a fired alert. Split out
/// so the emit contract is unit-testable without constructing a multi-day WAL.
async fn emit_alert(writer: &WalWriterHandle, alert: &TokenAnomalyAlert) -> Result<(), String> {
    let ts_unix = crate::time::now_unix_i64();
    let new_models: Vec<&str> = alert
        .kinds
        .iter()
        .filter_map(|k| match k {
            AnomalyKind::NewModel(m) => Some(m.as_str()),
            _ => None,
        })
        .collect();
    let tags: Vec<&str> = alert.kinds.iter().map(|k| k.tag()).collect();
    let payload = serde_json::to_vec(&serde_json::json!({
        "kinds": tags,
        "day_tokens": alert.day_tokens,
        "baseline_mean": alert.baseline_mean,
        "baseline_stddev": alert.baseline_stddev,
        "baseline_max": alert.baseline_max,
        "baseline_days": alert.baseline_days,
        "day_models": alert.day_models,
        "new_models": new_models,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize token-anomaly payload: {e}"))?;

    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_TOKEN_ANOMALY_DETECTED,
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

/// One token-anomaly cron pass: scan the WAL → evaluate the tripwire → on a
/// real trip emit `0x6E` and return `Ok(Some(alert))`. `Ok(None)` when there is
/// no anomaly (or not enough baseline). `wal_dir` is the daemon WAL dir
/// (`home/wal`).
pub async fn run_token_anomaly_tick(
    wal_dir: &Path,
    config: &TokenAnomalyConfig,
    writer: &WalWriterHandle,
) -> Result<Option<TokenAnomalyAlert>, String> {
    let by_day = scan_usage_by_day(wal_dir);
    let Some(alert) = evaluate_anomaly(&by_day, config) else {
        return Ok(None);
    };
    emit_alert(writer, &alert).await?;
    tracing::warn!(
        kinds = ?alert.kinds.iter().map(|k| k.tag()).collect::<Vec<_>>(),
        day_tokens = alert.day_tokens,
        baseline_mean = alert.baseline_mean,
        baseline_max = alert.baseline_max,
        baseline_days = alert.baseline_days,
        "token-anomaly tripwire: today's LLM token usage is anomalous — a leaked \
         provider key, a runaway loop, or an unexpected model route can look like \
         this. Review `neoth wal show --type token_anomaly_detected` + provider usage",
    );
    Ok(Some(alert))
}

/// Spawn the token-anomaly cron loop. Returns the `JoinHandle` so the daemon
/// tracks it; `None` when `config.enabled == false` (the default) so opt-out
/// operators carry no idle task. Interval is clamped to a 60s floor by
/// [`TokenAnomalyConfig::interval_duration`].
pub fn spawn_token_anomaly_cron_loop(
    config: TokenAnomalyConfig,
    wal_dir: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("token-anomaly cron disabled in config (token_anomaly.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            sigma = config.sigma_multiplier,
            abs_jump = config.abs_jump_tokens,
            "token-anomaly cron loop online (GOLD-ADAPT-JV-PRO-02)",
        );
        loop {
            ticker.tick().await;
            match run_token_anomaly_tick(&wal_dir, &config, &writer).await {
                Ok(Some(alert)) => tracing::info!(
                    kinds = ?alert.kinds.iter().map(|k| k.tag()).collect::<Vec<_>>(),
                    "token-anomaly cron: 0x6E emitted",
                ),
                Ok(None) => tracing::debug!("token-anomaly cron: no anomaly this tick"),
                Err(e) => tracing::error!(error = %e, "token-anomaly tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_TOKEN_ANOMALY_DETECTED;

    fn cfg() -> TokenAnomalyConfig {
        TokenAnomalyConfig {
            enabled: true,
            ..TokenAnomalyConfig::default()
        }
    }

    fn day(tokens: u64, models: &[&str]) -> DayUsage {
        DayUsage {
            tokens,
            models: models.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Build a buckets map with consecutive day indexes starting at 1000.
    fn buckets(days: &[DayUsage]) -> BTreeMap<u64, DayUsage> {
        days.iter()
            .enumerate()
            .map(|(i, u)| (1000 + i as u64, u.clone()))
            .collect()
    }

    #[test]
    fn no_anomaly_on_steady_usage() {
        let b = buckets(&[
            day(100_000, &["gpt"]),
            day(110_000, &["gpt"]),
            day(95_000, &["gpt"]),
            day(105_000, &["gpt"]),
        ]);
        assert!(evaluate_anomaly(&b, &cfg()).is_none());
    }

    #[test]
    fn insufficient_baseline_returns_none() {
        // Only two days total → baseline of 1 < min_baseline_days(3) → skip.
        let b = buckets(&[day(100_000, &["gpt"]), day(9_000_000, &["gpt"])]);
        assert!(evaluate_anomaly(&b, &cfg()).is_none());
    }

    #[test]
    fn sigma_spike_fires_on_a_clear_outlier() {
        let b = buckets(&[
            day(100_000, &["gpt"]),
            day(105_000, &["gpt"]),
            day(98_000, &["gpt"]),
            day(102_000, &["gpt"]),
            day(900_000, &["gpt"]), // ~8× the ~100k mean, far past 3σ
        ]);
        let a = evaluate_anomaly(&b, &cfg()).expect("clear outlier must trip");
        assert!(a.kinds.contains(&AnomalyKind::SigmaSpike), "{:?}", a.kinds);
        assert_eq!(a.day_tokens, 900_000);
    }

    #[test]
    fn flat_baseline_does_not_false_alarm_on_a_small_bump() {
        // stddev == 0 across the baseline; a tiny bump must NOT read as
        // "infinite σ" (the absolute-jump path handles real jumps).
        let b = buckets(&[
            day(100_000, &["gpt"]),
            day(100_000, &["gpt"]),
            day(100_000, &["gpt"]),
            day(120_000, &["gpt"]), // +20k, well under abs_jump_tokens(1M)
        ]);
        assert!(
            evaluate_anomaly(&b, &cfg()).is_none(),
            "a flat baseline + small bump must not trip the σ test"
        );
    }

    #[test]
    fn absolute_jump_fires_past_a_million_over_baseline_max() {
        let b = buckets(&[
            day(100_000, &["gpt"]),
            day(120_000, &["gpt"]),
            day(110_000, &["gpt"]),
            day(2_500_000, &["gpt"]), // +2.4M over the 120k baseline max
        ]);
        let a = evaluate_anomaly(&b, &cfg()).expect("a >1M jump must trip");
        assert!(
            a.kinds.contains(&AnomalyKind::AbsoluteJump),
            "{:?}",
            a.kinds
        );
    }

    #[test]
    fn new_model_fires_when_an_unseen_model_appears() {
        let b = buckets(&[
            day(100_000, &["gpt"]),
            day(105_000, &["gpt"]),
            day(98_000, &["gpt"]),
            day(101_000, &["gpt", "exfil-model"]), // steady volume, NEW model
        ]);
        let a = evaluate_anomaly(&b, &cfg()).expect("a new model must trip even at steady volume");
        assert!(
            a.kinds
                .iter()
                .any(|k| matches!(k, AnomalyKind::NewModel(m) if m == "exfil-model")),
            "{:?}",
            a.kinds
        );
    }

    #[test]
    fn min_absolute_floor_suppresses_low_volume_noise() {
        // A proportionally-large spike but tiny absolute tokens (under the
        // min_absolute_tokens floor) must NOT trip σ — a hobby operator who
        // does 200 tokens one day vs 50 the next isn't a security event.
        let b = buckets(&[
            day(50, &["gpt"]),
            day(60, &["gpt"]),
            day(40, &["gpt"]),
            day(2_000, &["gpt"]),
        ]);
        let a = evaluate_anomaly(&b, &cfg());
        assert!(
            a.is_none() || !a.unwrap().kinds.contains(&AnomalyKind::SigmaSpike),
            "sub-floor volume must not trip the σ tripwire"
        );
    }

    #[tokio::test]
    async fn scan_sums_tokens_and_collects_models_for_a_day() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        for (inp, out, model) in [(100u64, 50u64, "gpt"), (200, 80, "claude"), (10, 5, "gpt")] {
            let payload = serde_json::to_vec(&serde_json::json!({
                "model": model, "input_tokens": inp, "output_tokens": out,
            }))
            .unwrap();
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
                &payload,
            )
            .build();
            writer.append(header, payload).await.unwrap();
        }
        drop(writer);
        let _ = join.await;

        let by_day = scan_usage_by_day(dir.path());
        assert_eq!(by_day.len(), 1, "all frames land on today");
        let usage = by_day.values().next().unwrap();
        assert_eq!(usage.tokens, 100 + 50 + 200 + 80 + 10 + 5);
        assert_eq!(
            usage.models,
            ["claude", "gpt"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[tokio::test]
    async fn tick_on_empty_wal_dir_is_ok_none() {
        let dir = tempfile::tempdir().unwrap();
        // Bind the segment's TempDir: dropping it inline deletes the parent
        // before the writer opens it, and the writer refuses a missing parent.
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("w.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let out = run_token_anomaly_tick(dir.path(), &cfg(), &writer)
            .await
            .unwrap();
        assert!(out.is_none(), "no usage data → no anomaly");
    }

    #[tokio::test]
    async fn emit_alert_writes_a_decodable_0x6e_frame() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("alert.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let alert = TokenAnomalyAlert {
            kinds: vec![
                AnomalyKind::AbsoluteJump,
                AnomalyKind::NewModel("exfil-model".into()),
            ],
            day_tokens: 5_000_000,
            baseline_mean: 110_000.0,
            baseline_stddev: 8_000.0,
            baseline_max: 120_000,
            baseline_days: 4,
            day_models: vec!["gpt".into(), "exfil-model".into()],
        };
        emit_alert(&writer, &alert).await.unwrap();
        drop(writer);
        let _ = join.await;

        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let dec = crate::wal::frame::decode_frame(&bytes[hdr.header_len()..]).unwrap();
        assert_eq!(dec.header.event_type, EVENT_TYPE_TOKEN_ANOMALY_DETECTED);
        let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
        assert_eq!(v["day_tokens"], 5_000_000);
        assert_eq!(v["baseline_max"], 120_000);
        assert_eq!(v["kinds"][0], "absolute_jump");
        assert_eq!(v["new_models"][0], "exfil-model");
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let seg = tempfile::tempdir().unwrap().path().join("w.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = TokenAnomalyConfig::default(); // enabled = false
        let handle = spawn_token_anomaly_cron_loop(cfg, PathBuf::from("/tmp/wal"), writer);
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled_then_abort() {
        let seg = tempfile::tempdir().unwrap().path().join("w.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_token_anomaly_cron_loop(cfg(), PathBuf::from("/tmp/wal"), writer)
            .expect("enabled → handle");
        handle.abort();
    }
}
