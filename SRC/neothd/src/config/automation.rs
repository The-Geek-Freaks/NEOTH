//! Runtime automation and monitoring configuration.

use serde::{Deserialize, Serialize};

/// N-3 Workstream D (Session 23) — `freedom.yaml::n8n_api` shape.
///
/// Default OFF: a fresh install must explicitly flip `enabled: true`
/// + run `neoth n8n token` to bring the localhost HTTP API up. Port
/// pinned to [`crate::n8n_api::DEFAULT_N8N_API_PORT`] (9744) so the
/// bootstrap workflow JSONs at `assets/n8n_workflows/*.json` find
/// the daemon without operator-side surgery.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct N8nApiConfig {
    /// Master switch. Default `false` — the hyper task never spawns
    /// until the operator opts in.
    pub enabled: bool,
    /// Loopback port the hyper server binds. Defaults to
    /// `crate::n8n_api::DEFAULT_N8N_API_PORT` (9744). Override only
    /// when 9744 collides with another local service.
    pub port: u16,
    /// Override the bearer-token file location. `None` resolves to
    /// `~/.neoth/n8n_api_token` (mode-0600 / DACL-restricted).
    pub token_path: Option<std::path::PathBuf>,
}

impl Default for N8nApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: crate::n8n_api::DEFAULT_N8N_API_PORT,
            token_path: None,
        }
    }
}

/// C-16 (Session 21) — proactive messaging opt-in. Pure config
/// shape; the runtime gate consults `proactive.enabled` before
/// firing any unsolicited outbound. Default OFF.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProactiveConfig {
    /// Master switch. `false` = daemon never posts unsolicited
    /// messages (briefings stay opt-in-per-call via the cron yaml).
    /// `true` = cron + `send_proactive()` MAY post on their own.
    pub enabled: bool,
}

/// HO-09 / V1x-03 — profile baseline drift alerting. `neoth profile drift
/// report` flags drift over `threshold`; when `enabled`, the daemon
/// drift-alert cron (HO-09b, `daemon::drift_alert_cron`) emits a
/// `0xBA PROFILE_DRIFT_ALERT` WAL frame on the same threshold every
/// `interval_secs`. Default OFF so the common path is unaffected.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct DriftAlertConfig {
    /// Master switch for drift alerting. Default `false`.
    pub enabled: bool,
    /// Drift ratio above which the profile is "drifted". A report
    /// at-or-below this is informational; strictly above is flagged.
    /// The ratio ranges `0.0..=2.0` (0.0 = identical; 1.0 = full
    /// one-sided replacement; 2.0 = fully disjoint sets — see
    /// `baseline_diff::DriftReport::drift_ratio`). Default `0.25`
    /// (a quarter of the baseline churned).
    pub threshold: f64,
    /// Daemon drift-alert cron tick interval, seconds. Default 6h
    /// (drift changes slowly — claims accrete over days). Clamped to a
    /// 60s floor by [`Self::interval_duration`] so a misconfigured `0`
    /// can't tight-loop.
    pub interval_secs: u64,
}

/// 6 hours — the drift-alert cron default cadence.
pub const DEFAULT_DRIFT_ALERT_INTERVAL_SECS: u64 = 6 * 3600;

impl Default for DriftAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 0.25,
            interval_secs: DEFAULT_DRIFT_ALERT_INTERVAL_SECS,
        }
    }
}

impl DriftAlertConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    /// Mirrors `DoctorCronConfig::interval_duration`.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// GOLD-ADAPT-JV-PRO-02 — token-anomaly security tripwire config. When
/// `enabled`, a daemon cron buckets the WAL's `0x21 PROVIDER_RESPONSE` token
/// usage by UTC day and emits `0x6E TOKEN_ANOMALY_DETECTED` when the most
/// recent active day shows a σ-spike, a `>abs_jump_tokens` jump over the
/// baseline max, or a model unseen across the baseline window. Default OFF.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct TokenAnomalyConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 6h; clamped to a 60s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
    /// σ multiplier for the spike trigger (`day > mean + k·stddev`). Default 3.0.
    pub sigma_multiplier: f64,
    /// Absolute token jump over the baseline max that always trips, regardless
    /// of variance. Default 1,000,000.
    pub abs_jump_tokens: u64,
    /// How many days back the baseline window spans. Default 5.
    pub baseline_days: u32,
    /// Minimum baseline days WITH usage required before the tripwire runs (too
    /// little history = no meaningful baseline → skip). Default 3.
    pub min_baseline_days: u32,
    /// Absolute floor on a day's tokens before the σ trigger can fire — keeps a
    /// low-volume operator's day-to-day noise from tripping it. Default 50,000.
    pub min_absolute_tokens: u64,
}

/// 6 hours — the token-anomaly cron default cadence.
pub const DEFAULT_TOKEN_ANOMALY_INTERVAL_SECS: u64 = 6 * 3600;

impl Default for TokenAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_TOKEN_ANOMALY_INTERVAL_SECS,
            sigma_multiplier: 3.0,
            abs_jump_tokens: 1_000_000,
            baseline_days: 5,
            min_baseline_days: 3,
            min_absolute_tokens: 50_000,
        }
    }
}

impl TokenAnomalyConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// GOLD-ADAPT-VIEW-05 — session-health / outcome cron config. When `enabled`,
/// the daemon grades the most-recent active UTC day A–F from the WAL audit trail
/// (refusal-failures `0x1A`/`0x27` + job-failures `0x42` over `0x21` activity)
/// and emits `0x6F SESSION_HEALTH_DEGRADED` when the grade is at or below
/// `alert_at_or_below`. Default OFF.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct SessionHealthConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 6h; clamped to a 60s floor by
    /// [`Self::interval_duration`].
    pub interval_secs: u64,
    /// Minimum `0x21` replies a day needs before it is graded — a near-idle day
    /// is not meaningfully gradeable. Default 10.
    pub min_activity: u64,
    /// Alert when the recent day's grade is at or below this letter (`A`..`F`).
    /// Default `D`.
    pub alert_at_or_below: String,
    /// Regression alert: the most-recent day also alerts when its score falls
    /// more than this many points below the trailing baseline (a sharp
    /// "worse-than-usual" drop), even if its absolute grade is above
    /// `alert_at_or_below`. Default 20.0 (≈ one letter grade).
    pub regression_drop_threshold: f64,
    /// How many prior days form the regression baseline (a trailing mean of
    /// qualifying days). Default 7. Needs ≥3 qualifying days or the regression
    /// check is skipped (no false alerts on a fresh install).
    pub regression_baseline_days: u64,
    /// A regression alert ALSO requires the day's score to be below this floor,
    /// so a drop from an A-baseline into a still-healthy B never fires noise.
    /// Default 75.0 (the C/B boundary — only alert once the day is genuinely
    /// degraded). Set to 100.0 to alert on any baseline drop.
    pub regression_min_score_floor: f64,
}

/// 6 hours — the session-health cron default cadence.
pub const DEFAULT_SESSION_HEALTH_INTERVAL_SECS: u64 = 6 * 3600;

impl Default for SessionHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_SESSION_HEALTH_INTERVAL_SECS,
            min_activity: 10,
            alert_at_or_below: "D".to_string(),
            regression_drop_threshold: 20.0,
            regression_baseline_days: 7,
            regression_min_score_floor: 75.0,
        }
    }
}

impl SessionHealthConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// ADV-14 default tick interval: weekly (recall regressions are detected
/// against a cutover anchor; a weekly re-check is plenty + keeps the provider
/// + embed cost negligible).
pub const DEFAULT_REGRESSION_INTERVAL_SECS: u64 = 7 * 24 * 3600;

/// GOLD-FEAT-09 — daemon watchdog / auto-recovery cron config. When `enabled`,
/// the daemon probes the supervised local services (n8n / Ollama) every
/// `interval_secs`, and once a service has been down for
/// `consecutive_failures_before_restart` ticks it restarts it (only at
/// `Elevated`+ autonomy — below that it alerts only) under a per-window restart
/// budget (`max_restarts_per_window` per `window_secs`). Emits
/// `0x5F WATCHDOG_RESTART`. Default OFF (opt-in).
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct WatchdogConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Probe cadence, seconds. Default 60s. Clamped to a 10s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
    /// Restart only after this many consecutive failed probes. Default 3.
    pub consecutive_failures_before_restart: u32,
    /// Restart budget per `window_secs`. Default 3.
    pub max_restarts_per_window: u32,
    /// Restart-budget window length, seconds. Default 1h.
    pub window_secs: u64,
    /// TCP port the n8n service is probed on. Default 5678.
    pub n8n_port: u16,
    /// TCP port the Ollama service is probed on. Default 11434.
    pub ollama_port: u16,
    /// Exponential-backoff base between consecutive restarts of the SAME service,
    /// seconds. The Nth in-window restart must wait at least `base · 2^(N-1)`
    /// (capped at `restart_backoff_max_secs`) plus a small random jitter since the
    /// previous restart — so a flapping service is not hammered every tick even
    /// while restart budget remains. Default 30s. `0` disables backoff.
    pub restart_backoff_base_secs: u64,
    /// Cap on the exponential restart backoff, seconds. Default 900 (15 min).
    pub restart_backoff_max_secs: u64,
}

/// 1 hour — the watchdog restart-budget window default.
pub const DEFAULT_WATCHDOG_WINDOW_SECS: u64 = 3600;

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 60,
            consecutive_failures_before_restart: 3,
            max_restarts_per_window: 3,
            window_secs: DEFAULT_WATCHDOG_WINDOW_SECS,
            n8n_port: 5678,
            ollama_port: 11434,
            restart_backoff_base_secs: 30,
            restart_backoff_max_secs: 900,
        }
    }
}

impl WatchdogConfig {
    /// Probe interval as a `Duration`, clamped to a 10s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(10))
    }
}

/// ADV-14 — longitudinal recall-regression anchor cron config. When `enabled`,
/// the daemon weekly re-asks each anchor query, embeds the fresh answer, and
/// emits `0x3F REGRESSION_ALERT` when `cosine(current, anchor) < threshold` —
/// durable evidence that the model's answer to a known query has drifted after
/// a model/config change. Default OFF (opt-in; needs a configured embed
/// provider + a captured anchor file under `~/.neoth/eval/`).
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RegressionAnchorConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Cosine floor. An anchor whose fresh answer scores STRICTLY BELOW this
    /// against its cutover vector is flagged. Range `0.0..=1.0`. Default `0.70`.
    pub threshold: f32,
    /// Tick interval, seconds. Default weekly. Clamped to a 60s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
}

impl Default for RegressionAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 0.70,
            interval_secs: DEFAULT_REGRESSION_INTERVAL_SECS,
        }
    }
}

impl RegressionAnchorConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum (mirrors
    /// `DriftAlertConfig::interval_duration`) so `interval_secs: 0` can't
    /// tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// MONITOR-03 default tick interval: 6h (recall p95 changes slowly; the
/// runbook checks it a few times a day).
pub const DEFAULT_RECALL_LATENCY_INTERVAL_SECS: u64 = 6 * 3600;

/// MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert cron config. When
/// `enabled`, the daemon reads the recent `idx_recall_latency` window and
/// emits `0x4B RECALL_LATENCY_ALERT` when p95 exceeds `p95_threshold_ms`
/// (and at least `min_samples` samples exist — a 2-query window isn't a
/// meaningful p95). Default OFF.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RecallLatencyConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// p95 ceiling in milliseconds. A window whose p95 STRICTLY exceeds this is
    /// flagged. Default `750.0` (local FTS5 recall is normally single-digit ms;
    /// 750ms p95 signals a cold cache / disk pressure / index regression).
    pub p95_threshold_ms: f64,
    /// Don't alert until at least this many samples exist in the window — a
    /// handful of queries don't make a trustworthy p95. Default `20`.
    pub min_samples: usize,
    /// How many of the most-recent samples to compute p95 over. Default `200`.
    pub window: usize,
    /// Tick interval, seconds. Default 6h. Clamped to a 60s floor.
    pub interval_secs: u64,
}

impl Default for RecallLatencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            p95_threshold_ms: 750.0,
            min_samples: 20,
            window: 200,
            interval_secs: DEFAULT_RECALL_LATENCY_INTERVAL_SECS,
        }
    }
}

impl RecallLatencyConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so
    /// `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// SL-03 — ResourcePressureWatcher cron config. When `enabled`, the
/// daemon polls live GPU VRAM every `interval_secs` and emits a
/// `0x47 RESOURCE_PRESSURE_ALERT` when usage `>= vram_threshold_pct`.
/// Default OFF (opt-in). No-op on non-GPU / non-NVIDIA hosts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ResourceWatchConfig {
    /// Master switch. `false` (default) = the cron never spawns.
    pub enabled: bool,
    /// Poll interval in seconds. Default 30. Clamped to a 10s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
    /// VRAM-usage percent at-or-above which an advisory frame is emitted.
    /// Default 90.
    pub vram_threshold_pct: u8,
}

/// 30 seconds — the resource-watch cron default cadence.
pub const DEFAULT_RESOURCE_WATCH_INTERVAL_SECS: u64 = 30;

impl Default for ResourceWatchConfig {
    fn default() -> Self {
        // Off by default — opt-in gate per the noob-wizard rule.
        Self {
            enabled: false,
            interval_secs: DEFAULT_RESOURCE_WATCH_INTERVAL_SECS,
            vram_threshold_pct: 90,
        }
    }
}

impl ResourceWatchConfig {
    /// Poll interval as a `Duration`, clamped to a 10s floor so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(10))
    }
}

/// HO-07 — neoth-monitor alerting cron config. When `enabled`, the daemon
/// scans the WAL + crash log every `interval_secs` and emits advisory
/// frames when anomalies are detected:
///   - `0x48 WAL_CRC_ALERT` when RECOVERY_TRUNCATED / COMPACTION_AUTH_FAILED
///     frames appear in the `wal_crc_window_secs` look-back
///   - `0x49 CRASH_LOG_ALERT` when new content arrives in `crash.log`
///   - `0x4A CHANNEL_SILENCE_ALERT` when no CHANNEL_INGRESS/EGRESS frames
///     appear for `channel_silence_secs` during the active UTC window
///
/// Default OFF. No-op when the WAL dir is empty / crash.log absent.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct MonitorConfig {
    /// Master switch. `false` (default) = the cron never spawns.
    pub enabled: bool,
    /// Poll interval in seconds. Default 300 (5 min). Clamped to 30s floor.
    pub interval_secs: u64,
    /// Look-back window for WAL CRC anomaly counting, seconds. Default 3600 (1h).
    pub wal_crc_window_secs: u64,
    /// Channel silence threshold in seconds. Default 1800 (30 min).
    pub channel_silence_secs: u64,
    /// UTC hour (0-23) when the active channel-watch window OPENS.
    /// Default 7 (07:00 UTC ≈ 08:00 CET / 09:00 CEST).
    pub channel_silence_active_utc_start: u8,
    /// UTC hour (0-23) when the active channel-watch window CLOSES.
    /// Default 21 (21:00 UTC ≈ 22:00 CET / 23:00 CEST).
    pub channel_silence_active_utc_end: u8,
    /// MONITOR-04 — minimum seconds between repeated alerts of the SAME kind.
    /// The monitor re-checks state every tick; without this it re-emits
    /// `0x48`/`0x4A` on every tick the bad state persists (CRC frames linger in
    /// the look-back window; channel silence is level- not edge-triggered).
    /// Default 3600 (1h): emit-once-per-hour-per-kind. `0` disables dedup.
    /// (Crash alerts are already edge-triggered via the crash.log byte offset,
    /// so dedup is moot for them.)
    pub min_repeat_alert_secs: u64,
}

/// 5 minutes — the monitor cron default cadence.
pub const DEFAULT_MONITOR_INTERVAL_SECS: u64 = 300;

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_MONITOR_INTERVAL_SECS,
            wal_crc_window_secs: 3600,
            channel_silence_secs: 1800,
            channel_silence_active_utc_start: 7,
            channel_silence_active_utc_end: 21,
            min_repeat_alert_secs: 3600,
        }
    }
}

impl MonitorConfig {
    /// Poll interval as a `Duration`, clamped to a 30s floor.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(30))
    }
}

/// SPEC-05 — passive user-adaptation cron config. When `enabled`, the
/// daemon re-aggregates the behavioural snapshot + generates self-dev
/// proposals every `interval_secs`. Default OFF (opt-in), matching the
/// `drift_alert` precedent — the proposals are non-destructive (pending
/// operator review) but the aggregation scans the WAL, so it stays
/// opt-in until the operator wants proactive adaptation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ProfileAdaptConfig {
    /// Master switch for the passive-adaptation cron. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 24h — behavioural patterns
    /// shift over days, so daily re-aggregation is ample. Clamped to a
    /// 60s floor by [`Self::interval_duration`].
    pub interval_secs: u64,
}

// NOTE: the cron computes proposals *against* the operator's chosen
// behavioural preset, but that choice is NOT stored here — it lives in the
// single canonical active-preset marker (`cli::profile::{record,load}_active_preset`,
// set by `neoth profile preset set` / the GUI selector). The cron reads it
// live each tick via `load_active_preset`, so there is exactly one source of
// truth for "the operator's behavioural preset".

/// 24 hours — the passive-adaptation cron default cadence.
pub const DEFAULT_PROFILE_ADAPT_INTERVAL_SECS: u64 = 24 * 3600;

impl Default for ProfileAdaptConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_PROFILE_ADAPT_INTERVAL_SECS,
        }
    }
}

impl ProfileAdaptConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// G-01 — passive behaviour-pattern cron config. When `enabled`, the
/// daemon's `pattern_cron` runs every `interval_secs` and fires up to
/// four independent detectors, each enqueueing at most ONE proactive
/// nudge per UTC day (deduped):
///   - **inactivity-gap**: silence longer than `inactivity_gap_secs`.
///   - **query-repeat**: the same message asked `query_repeat_min_count`+
///     times within `query_repeat_window_secs` (candidate for a saved
///     note/shortcut/skill).
///   - **topic-burst**: a topic whose recent mention-rate spikes by
///     `topic_burst_factor`× over its baseline (focus shift).
///   - **time-of-day-shift**: the operator's peak active hour moved by
///     `tod_shift_min_hours`+ hours.
/// Master `enabled` is OFF by default — a proactive ping is intrusive,
/// so the whole engine stays opt-in (matching `drift_alert`/
/// `profile_adapt`). Once opted in, each detector has its own toggle so
/// an operator can keep, say, inactivity + query-repeat but silence the
/// topic-burst nudges.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PatternCronConfig {
    /// Master switch for the whole pattern engine. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 24h.
    pub interval_secs: u64,
    /// Quiet-gap threshold, seconds, beyond which an inactivity nudge
    /// fires. Default 3 days — long enough that a normal weekend pause
    /// stays silent.
    pub inactivity_gap_secs: u64,

    // --- query-repeat detector ---
    /// Enable the query-repeat detector. Default `true` (within the
    /// opt-in engine).
    pub query_repeat_enabled: bool,
    /// Look-back window for repeated-message detection, seconds.
    /// Default 7 days.
    pub query_repeat_window_secs: u64,
    /// How many byte-identical messages within the window trigger a
    /// nudge. Default 3.
    pub query_repeat_min_count: u32,

    // --- topic-burst detector ---
    /// Enable the topic-burst detector. Default `true`.
    pub topic_burst_enabled: bool,
    /// Recent window for burst detection, seconds. Default 2 days.
    pub topic_burst_recent_secs: u64,
    /// Total baseline window, seconds. The baseline period the recent
    /// rate is compared against is `baseline_secs - recent_secs`.
    /// Default 14 days.
    pub topic_burst_baseline_secs: u64,
    /// Absolute floor: a topic must appear at least this many times in
    /// the recent window before it can burst (drops one-off noise).
    /// Default 4.
    pub topic_burst_min_count: u32,
    /// Burst factor: recent mention-rate must exceed this multiple of
    /// the baseline rate. Default 3.0. (A brand-new topic with zero
    /// baseline always passes once over the min-count floor.)
    pub topic_burst_factor: f64,

    // --- time-of-day-shift detector ---
    /// Enable the time-of-day-shift detector. Default `true`.
    pub tod_shift_enabled: bool,
    /// Recent window for the peak-hour histogram, seconds. Default
    /// 7 days.
    pub tod_shift_recent_secs: u64,
    /// Baseline window for the peak-hour histogram, seconds. The
    /// compared baseline period is `baseline_secs - recent_secs`.
    /// Default 30 days.
    pub tod_shift_baseline_secs: u64,
    /// Minimum circular distance (hours) between the recent and baseline
    /// peak active hour before a shift nudge fires. Default 4.
    pub tod_shift_min_hours: u32,
    /// Minimum episodes required in EACH window before the histogram is
    /// trusted (sparse data gives a noisy peak). Default 10.
    pub tod_shift_min_episodes: u32,

    /// Max nudges the pattern engine enqueues in a SINGLE tick across all
    /// detectors. Highest-priority detectors win the slots. Default 1 so
    /// the engine takes at most a third of the shared 3/day ProactiveQueue
    /// budget per tick, leaving room for the reflection + g02 producers.
    /// Clamped to a 1 floor downstream (0 would silence the engine).
    pub max_nudges_per_tick: u32,
}

/// 24 hours — the pattern cron default cadence.
pub const DEFAULT_PATTERN_CRON_INTERVAL_SECS: u64 = 24 * 3600;
/// 3 days — the default inactivity gap before a nudge.
pub const DEFAULT_INACTIVITY_GAP_SECS: u64 = 3 * 24 * 3600;

impl Default for PatternCronConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_PATTERN_CRON_INTERVAL_SECS,
            inactivity_gap_secs: DEFAULT_INACTIVITY_GAP_SECS,
            query_repeat_enabled: true,
            query_repeat_window_secs: 7 * 24 * 3600,
            query_repeat_min_count: 3,
            topic_burst_enabled: true,
            topic_burst_recent_secs: 2 * 24 * 3600,
            topic_burst_baseline_secs: 14 * 24 * 3600,
            topic_burst_min_count: 4,
            topic_burst_factor: 3.0,
            tod_shift_enabled: true,
            tod_shift_recent_secs: 7 * 24 * 3600,
            tod_shift_baseline_secs: 30 * 24 * 3600,
            tod_shift_min_hours: 4,
            tod_shift_min_episodes: 10,
            max_nudges_per_tick: 1,
        }
    }
}

impl PatternCronConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// GOLD-ADAPT-ODY-07 — background-job monitor config.
///
/// When `interval_secs > 0` (default 5), `spawn_bg_monitor` scans
/// `~/.neoth/bgjobs/` for completed detached subprocess jobs and fires
/// auto-continue callbacks. The monitor is always-on infrastructure
/// (no bgjobs = no auto-continue), so `interval_secs` defaults to 5s
/// rather than 0. Operators who want to disable it entirely set
/// `bg_monitor.interval_secs: 0` in freedom.yaml.
///
/// `interval_secs: 0` disables the monitor entirely (no task spawns).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct BgMonitorConfig {
    /// Scan interval in seconds. Default 5. `0` = disabled (no task spawns).
    pub interval_secs: u64,
}

impl Default for BgMonitorConfig {
    fn default() -> Self {
        Self { interval_secs: 5 }
    }
}

/// GOLD-ADAPT-JV-MEM-16 — guidance-block snapshot refresh cron.
///
/// When `enabled`, the daemon scans the WAL + scorecard every
/// `interval_secs` (default 3h) and writes
/// `~/.neoth/guidance_snapshot.json` so the next `build_prompt_bundle`
/// reads richer context (freshness + 24h signals + cron errors).
///
/// Default OFF so a fresh install carries zero idle overhead; the
/// operator enables via `freedom.yaml::guidance_cron.enabled: true`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct GuidanceCronConfig {
    /// Master switch. Default `false` (opt-in).
    pub enabled: bool,
    /// Snapshot refresh interval in seconds. Default 10800 (3h). Floor 60s.
    pub interval_secs: u64,
    /// Look-back window for 24h-signal counting in seconds. Default 86400 (24h).
    pub signal_window_secs: u64,
}

/// Default snapshot refresh interval: 3 hours.
pub const DEFAULT_GUIDANCE_CRON_INTERVAL_SECS: u64 = 10_800;

impl Default for GuidanceCronConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_GUIDANCE_CRON_INTERVAL_SECS,
            signal_window_secs: 86_400,
        }
    }
}

impl GuidanceCronConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum.
    pub fn interval_duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

// ── NN-MEM-02 — 5-dimensional synthesis pattern-recognition cron ─────────────

/// Default run interval: once per week (7 days).
pub const DEFAULT_SYNTHESIS_CRON_INTERVAL_SECS: u64 = 604_800;

/// Default look-back window for episode analysis: 30 days.
pub const DEFAULT_SYNTHESIS_WINDOW_DAYS: u64 = 30;

/// Configuration for the synthesis pattern-recognition cron (maps to
/// `freedom.yaml::synthesis_cron`). All fields are `#[serde(default)]`
/// so old `freedom.yaml` files without this section parse correctly.
///
/// NN-MEM-02: weekly 5-dimensional pass over `idx_episode` /
/// `idx_groundtruth` / `idx_contradictions` → structured synthesis note
/// written as a `idx_groundtruth` row (`source = "synthesis-cron"`) and
/// optionally to `~/.neoth/synthesis/YYYY-WW.md`. Default OFF.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct SynthesisCronConfig {
    /// Master switch. Default `false` (opt-in).
    pub enabled: bool,
    /// Run interval in seconds. Default 604800 (7 days). Floor 60s.
    pub interval_secs: u64,
    /// Episode look-back window in days. Default 30.
    pub window_days: u64,
    /// NN-MEM-05: enable the SWIRL-style skill-performance dimension within the
    /// synthesis pass. Reads `~/.neoth/self_improve_log.json` and emits
    /// skill-prompt improvement suggestions. Default `false` (opt-in within the
    /// synthesis_cron opt-in, since it needs the SkillOpt ledger to have data).
    /// No-op when the ledger is empty.
    pub enable_skill_perf_pass: bool,
}

impl Default for SynthesisCronConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_SYNTHESIS_CRON_INTERVAL_SECS,
            window_days: DEFAULT_SYNTHESIS_WINDOW_DAYS,
            enable_skill_perf_pass: false,
        }
    }
}

impl SynthesisCronConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum.
    pub fn interval_duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}
