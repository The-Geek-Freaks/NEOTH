//! Collapse label detection — computable functions over the event stream.
//!
//! Every label is a deterministic function of the WAL event stream in the window.
//! These definitions constitute the "pre-registration equivalent" required by
//! the falsification protocol — they MUST NOT be changed after data collection
//! begins without being declared as exploratory analysis.
//!
//! ## Label definitions (v0, frozen 2026-07-02)
//!
//! | Label | Detection rule |
//! |-------|---------------|
//! | `agent_loop` | event_type=retry appears ≥3 times with identical (tool, agent_id) within a 60-second sub-window |
//! | `retry_storm` | retry events exceed 5 per 30-second sub-window across all agents |
//! | `tool_timeout_cascade` | tool_timeout or error_kind containing "timeout" exceeds 3 distinct tool_id values in the window |
//! | `context_limit_failure` | context_used_ratio >= 0.95 followed by an error_kind containing "context" or "truncation" within the same session |
//! | `semantic_degradation` | K_d > 0.90 for 3 consecutive 5-minute sub-windows |
//! | `fallback_failure` | fallback_attempt event NOT followed by a fallback_result with success=true within 60 seconds |
//! | `objective_failure` | operator-labelled or CLI `neoth babel label <window_id> objective_failure` |
//!
//! `tool_selection_failure` from the integration doc is subsumed by
//! `tool_timeout_cascade` (see docs/neoth-integration.md note).

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// The 8 canonical collapse labels, matching the enum in the JSON schema
/// (event schema v0.1.1 / window schema v0.4.0 — `tool_selection_failure`
/// added upstream in delta-kosmologie `a4bd367`, FINDING-09).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollapseLabel {
    AgentLoop,
    RetryStorm,
    ToolTimeoutCascade,
    ContextLimitFailure,
    SemanticDegradation,
    FallbackFailure,
    ObjectiveFailure,
    /// Operator/CLI-labelled only in v0 (no automatic detector), like
    /// `objective_failure`.
    ToolSelectionFailure,
}

impl std::str::FromStr for CollapseLabel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "agent_loop" => Self::AgentLoop,
            "retry_storm" => Self::RetryStorm,
            "tool_timeout_cascade" => Self::ToolTimeoutCascade,
            "context_limit_failure" => Self::ContextLimitFailure,
            "semantic_degradation" => Self::SemanticDegradation,
            "fallback_failure" => Self::FallbackFailure,
            "objective_failure" => Self::ObjectiveFailure,
            "tool_selection_failure" => Self::ToolSelectionFailure,
            other => anyhow::bail!(
                "unknown collapse label `{other}` (expected one of: agent_loop, retry_storm, \
                 tool_timeout_cascade, context_limit_failure, semantic_degradation, \
                 fallback_failure, objective_failure, tool_selection_failure)"
            ),
        })
    }
}

impl CollapseLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentLoop => "agent_loop",
            Self::RetryStorm => "retry_storm",
            Self::ToolTimeoutCascade => "tool_timeout_cascade",
            Self::ContextLimitFailure => "context_limit_failure",
            Self::SemanticDegradation => "semantic_degradation",
            Self::FallbackFailure => "fallback_failure",
            Self::ObjectiveFailure => "objective_failure",
            Self::ToolSelectionFailure => "tool_selection_failure",
        }
    }
}

/// Output of the collapse label detector for one window.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollapseDetection {
    /// Whether any collapse label fired in the prediction horizon.
    pub collapse_within_5m: bool,
    pub collapse_within_30m: Option<bool>,
    /// The first label that fired, for stratified analysis.
    pub collapse_kind: Option<CollapseLabel>,
    /// Is this window a negative control (deliberately stable run)?
    pub negative_control: bool,
    pub negative_control_type: Option<NegativeControlType>,
}

/// Negative control classification — operator-tagged stable runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeControlType {
    /// Single-agent, single-tool, no-retry deterministic run.
    SyntheticStable,
    /// Isolated run with no multi-agent routing.
    IsolatedRun,
    /// Deterministic replay of a known-stable session.
    ReplayDeterministic,
}

impl NegativeControlType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticStable => "synthetic_stable",
            Self::IsolatedRun => "isolated_run",
            Self::ReplayDeterministic => "replay_deterministic",
        }
    }
}

impl std::str::FromStr for NegativeControlType {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "synthetic_stable" => Ok(Self::SyntheticStable),
            "isolated_run" => Ok(Self::IsolatedRun),
            "replay_deterministic" => Ok(Self::ReplayDeterministic),
            other => anyhow::bail!(
                "unknown negative-control type `{other}` (expected one of: \
                 synthetic_stable, isolated_run, replay_deterministic)"
            ),
        }
    }
}

/// Minimal event record for collapse detection — stripped of all content.
/// Populated from WAL event metadata only (no payloads containing operator text).
#[derive(Clone, Debug)]
pub struct CollapseEventRecord {
    pub ts_unix: i64,
    /// Coarsened to provider+family ("anthropic/claude-3"), never exact model id.
    pub event_type: CollapseEventType,
    pub agent_id: Option<String>,
    pub tool: Option<String>,
    pub success: Option<bool>,
    pub error_kind: Option<String>,
    pub context_used_ratio: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollapseEventType {
    Retry,
    ToolTimeout,
    ToolError,
    ContextBoundary,
    FallbackAttempt,
    FallbackResult,
    InferenceEnd,
    OperatorLabel,
}

/// Detect all firing labels from an ordered slice of event records.
/// Returns the first firing label (lowest ts_unix among all detectors).
pub fn detect_collapse(events: &[CollapseEventRecord], k_d_series: &[f64]) -> CollapseDetection {
    let mut labels: Vec<(i64, CollapseLabel)> = Vec::new();

    if let Some(ts) = detect_agent_loop(events) {
        labels.push((ts, CollapseLabel::AgentLoop));
    }
    if let Some(ts) = detect_retry_storm(events) {
        labels.push((ts, CollapseLabel::RetryStorm));
    }
    if let Some(ts) = detect_tool_timeout_cascade(events) {
        labels.push((ts, CollapseLabel::ToolTimeoutCascade));
    }
    if let Some(ts) = detect_context_limit_failure(events) {
        labels.push((ts, CollapseLabel::ContextLimitFailure));
    }
    if detect_semantic_degradation(k_d_series) {
        let ts = events.first().map(|e| e.ts_unix).unwrap_or(0);
        labels.push((ts, CollapseLabel::SemanticDegradation));
    }
    if let Some(ts) = detect_fallback_failure(events) {
        labels.push((ts, CollapseLabel::FallbackFailure));
    }
    if let Some(ts) = detect_objective_failure(events) {
        labels.push((ts, CollapseLabel::ObjectiveFailure));
    }

    labels.sort_by_key(|(ts, _)| *ts);
    let fired = !labels.is_empty();
    let kind = labels.into_iter().next().map(|(_, l)| l);

    CollapseDetection {
        collapse_within_5m: fired,
        collapse_within_30m: None, // populated by the 30m window aggregator
        collapse_kind: kind,
        negative_control: false,
        negative_control_type: None,
    }
}

// ── Individual detectors ─────────────────────────────────────────────────────

/// agent_loop: identical (tool, agent_id) retry tuple ≥3 times within 60s.
fn detect_agent_loop(events: &[CollapseEventRecord]) -> Option<i64> {
    let retries: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == CollapseEventType::Retry)
        .collect();
    let mut counts: std::collections::HashMap<(String, String), Vec<i64>> =
        std::collections::HashMap::new();
    for ev in &retries {
        let key = (
            ev.tool.clone().unwrap_or_default(),
            ev.agent_id.clone().unwrap_or_default(),
        );
        counts.entry(key).or_default().push(ev.ts_unix);
    }
    for (_key, mut ts_list) in counts {
        ts_list.sort_unstable();
        // Sliding window: any 3 events within 60s?
        for window in ts_list.windows(3) {
            if window[2] - window[0] <= 60 {
                return Some(window[0]);
            }
        }
    }
    None
}

/// retry_storm: >5 retry events in any 30-second sub-window.
fn detect_retry_storm(events: &[CollapseEventRecord]) -> Option<i64> {
    let mut retry_ts: Vec<i64> = events
        .iter()
        .filter(|e| e.event_type == CollapseEventType::Retry)
        .map(|e| e.ts_unix)
        .collect();
    retry_ts.sort_unstable();
    for window in retry_ts.windows(6) {
        if window[5] - window[0] <= 30 {
            return Some(window[0]);
        }
    }
    None
}

/// tool_timeout_cascade: >3 distinct tool ids with timeout/error in the window.
fn detect_tool_timeout_cascade(events: &[CollapseEventRecord]) -> Option<i64> {
    let timeout_tools: std::collections::HashSet<_> = events
        .iter()
        .filter(|e| {
            e.event_type == CollapseEventType::ToolTimeout
                || (e.event_type == CollapseEventType::ToolError
                    && e.error_kind
                        .as_deref()
                        .map(|s| s.contains("timeout"))
                        .unwrap_or(false))
        })
        .filter_map(|e| e.tool.as_deref())
        .collect();
    if timeout_tools.len() > 3 {
        // Timestamp of the earliest timeout/error evidence in the window
        // (not the 4th distinct tool — earliest onset is what the horizon
        // analysis wants).
        events
            .iter()
            .filter(|e| {
                e.event_type == CollapseEventType::ToolTimeout
                    || e.event_type == CollapseEventType::ToolError
            })
            .find(|e| e.tool.is_some())
            .map(|e| e.ts_unix)
    } else {
        None
    }
}

/// context_limit_failure: context_used_ratio >= 0.95 then error with "context"/"truncation".
fn detect_context_limit_failure(events: &[CollapseEventRecord]) -> Option<i64> {
    let mut near_limit_ts: Option<i64> = None;
    for ev in events {
        if ev.event_type == CollapseEventType::ContextBoundary
            && ev.context_used_ratio.map(|r| r >= 0.95).unwrap_or(false)
        {
            near_limit_ts = Some(ev.ts_unix);
        }
        if let Some(ts) = near_limit_ts
            && (ev.event_type == CollapseEventType::ToolError
                || ev.event_type == CollapseEventType::InferenceEnd)
            && ev
                .error_kind
                .as_deref()
                .map(|s| s.contains("context") || s.contains("truncation"))
                .unwrap_or(false)
        {
            return Some(ts);
        }
    }
    None
}

/// semantic_degradation: K_d > 0.90 for 3 consecutive 5-minute values.
fn detect_semantic_degradation(k_d_series: &[f64]) -> bool {
    if k_d_series.len() < 3 {
        return false;
    }
    k_d_series.windows(3).any(|w| w.iter().all(|&k| k > 0.90))
}

/// fallback_failure: fallback_attempt not followed by success=true within 60s.
fn detect_fallback_failure(events: &[CollapseEventRecord]) -> Option<i64> {
    for ev in events
        .iter()
        .filter(|e| e.event_type == CollapseEventType::FallbackAttempt)
    {
        let deadline = ev.ts_unix + 60;
        let succeeded = events.iter().any(|r| {
            r.event_type == CollapseEventType::FallbackResult
                && r.ts_unix <= deadline
                && r.ts_unix >= ev.ts_unix
                && r.success == Some(true)
        });
        if !succeeded {
            return Some(ev.ts_unix);
        }
    }
    None
}

/// objective_failure: explicit operator-label event in stream.
fn detect_objective_failure(events: &[CollapseEventRecord]) -> Option<i64> {
    events
        .iter()
        .find(|e| e.event_type == CollapseEventType::OperatorLabel)
        .map(|e| e.ts_unix)
}

// ── GOLD-DELTA-07 — label persistence ────────────────────────────────────────

/// Upsert one label row. `human_confirmed` only ever ratchets UP — an
/// automated re-pass must never demote an operator confirmation.
fn upsert_label_row(
    conn: &Connection,
    window_id: &str,
    label: &str,
    human_confirmed: bool,
    now_unix: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO idx_babel_labels (window_id, label, human_confirmed, labeled_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (window_id, label) DO UPDATE SET
           human_confirmed = MAX(idx_babel_labels.human_confirmed, excluded.human_confirmed),
           labeled_at = excluded.labeled_at",
        rusqlite::params![window_id, label, i64::from(human_confirmed), now_unix],
    )?;
    Ok(())
}

/// Persist a collapse label for a window (operator CLI `neoth babel label`
/// passes `human_confirmed = true`; automated detectors pass `false`).
/// Labels live in `idx_babel_labels` only — the window row itself is not
/// mutated (the export pipeline LEFT JOINs).
pub fn persist_label(
    conn: &Connection,
    window_id: &str,
    label: CollapseLabel,
    human_confirmed: bool,
    now_unix: i64,
) -> Result<()> {
    upsert_label_row(conn, window_id, label.as_str(), human_confirmed, now_unix)
}

/// Post-hoc horizon pass: stamp `collapse_30m` on every window whose
/// look-ahead horizon is now fully observable.
///
/// The WAL events are gone by the time a horizon ripens, so the pass is
/// DB-only: a window W collapsed-within-horizon iff some 5-minute window
/// with `collapse_5m = 1` STARTED inside `[W.ts_end, W.ts_end + look_ahead)`
/// (the 5-min windows are the in-window detectors; their flags are the
/// ground signal). A hit also writes the collapse kind into
/// `idx_babel_labels` (machine label, `human_confirmed = 0`); a fully
/// observed horizon with no hit stamps `collapse_30m = 0`. Returns the
/// number of windows stamped.
pub fn post_hoc_label_pass(
    conn: &Connection,
    look_ahead_secs: i64,
    now_unix: i64,
) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT id, ts_end FROM idx_babel_windows
         WHERE collapse_30m IS NULL AND ts_end + ?1 <= ?2",
    )?;
    let ripe: Vec<(String, i64)> = stmt
        .query_map(rusqlite::params![look_ahead_secs, now_unix], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut stamped = 0usize;
    for (id, ts_end) in ripe {
        let hit: Option<Option<String>> = conn
            .query_row(
                "SELECT collapse_kind FROM idx_babel_windows
                 WHERE window_secs = 300 AND collapse_5m = 1
                   AND ts_start >= ?1 AND ts_start < ?1 + ?2
                 ORDER BY ts_start ASC LIMIT 1",
                rusqlite::params![ts_end, look_ahead_secs],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        match hit {
            Some(kind) => {
                // Label BEFORE stamp: if the label upsert fails, the window
                // stays collapse_30m = NULL and the next pass retries both
                // (the upsert is idempotent) — stamp-first would strand a
                // collapse_30m = 1 row with no label forever.
                if let Some(kind) = kind {
                    upsert_label_row(conn, &id, &kind, false, now_unix)?;
                }
                conn.execute(
                    "UPDATE idx_babel_windows SET collapse_30m = 1 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
            }
            None => {
                conn.execute(
                    "UPDATE idx_babel_windows SET collapse_30m = 0 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
            }
        }
        stamped += 1;
    }
    Ok(stamped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry_event(ts: i64, tool: &str, agent: &str) -> CollapseEventRecord {
        CollapseEventRecord {
            ts_unix: ts,
            event_type: CollapseEventType::Retry,
            agent_id: Some(agent.into()),
            tool: Some(tool.into()),
            success: None,
            error_kind: None,
            context_used_ratio: None,
        }
    }

    #[test]
    fn agent_loop_fires_on_three_identical_retries_within_60s() {
        let events = vec![
            retry_event(0, "bash", "agent_a"),
            retry_event(30, "bash", "agent_a"),
            retry_event(55, "bash", "agent_a"),
        ];
        assert!(detect_agent_loop(&events).is_some());
    }

    #[test]
    fn agent_loop_does_not_fire_when_spread_beyond_60s() {
        let events = vec![
            retry_event(0, "bash", "agent_a"),
            retry_event(40, "bash", "agent_a"),
            retry_event(61, "bash", "agent_a"),
        ];
        assert!(detect_agent_loop(&events).is_none());
    }

    #[test]
    fn retry_storm_fires_on_six_retries_within_30s() {
        let events: Vec<_> = (0..6).map(|i| retry_event(i * 4, "any", "any")).collect();
        assert!(detect_retry_storm(&events).is_some());
    }

    #[test]
    fn semantic_degradation_requires_three_consecutive_high_k() {
        assert!(detect_semantic_degradation(&[0.95, 0.92, 0.91]));
        assert!(!detect_semantic_degradation(&[0.95, 0.85, 0.91]));
        assert!(!detect_semantic_degradation(&[0.95, 0.92]));
    }

    #[test]
    fn collapse_label_as_str_round_trips() {
        assert_eq!(CollapseLabel::AgentLoop.as_str(), "agent_loop");
        assert_eq!(
            CollapseLabel::SemanticDegradation.as_str(),
            "semantic_degradation"
        );
    }

    #[test]
    fn negative_control_type_round_trips_canonical_wire_values() {
        for value in [
            NegativeControlType::SyntheticStable,
            NegativeControlType::IsolatedRun,
            NegativeControlType::ReplayDeterministic,
        ] {
            assert_eq!(
                value.as_str().parse::<NegativeControlType>().unwrap(),
                value
            );
        }
        assert!("syntheticstable".parse::<NegativeControlType>().is_err());
    }

    const T: i64 = 1_800_000_000;

    fn labels_db() -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        super::super::store::ensure_schema(&conn).expect("schema");
        conn
    }

    fn seed_window(
        conn: &Connection,
        id: &str,
        window_secs: i64,
        ts_end: i64,
        collapse_5m: Option<i64>,
        kind: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables,
              collapse_5m, collapse_kind)
             VALUES (?1, 'a1b2c3d4e5f60718', ?2, ?3, ?4, 0.5, '{}', ?5, ?6)",
            rusqlite::params![
                id,
                window_secs,
                ts_end - window_secs,
                ts_end,
                collapse_5m,
                kind
            ],
        )
        .expect("seed window");
    }

    #[test]
    fn persist_label_upsert_never_demotes_human_confirmation() {
        let conn = labels_db();
        persist_label(&conn, "w1", CollapseLabel::AgentLoop, true, 100).expect("human label");
        persist_label(&conn, "w1", CollapseLabel::AgentLoop, false, 200).expect("machine re-pass");
        let (confirmed, at, count): (i64, i64, i64) = conn
            .query_row(
                "SELECT human_confirmed, labeled_at,
                        (SELECT COUNT(*) FROM idx_babel_labels)
                 FROM idx_babel_labels WHERE window_id = 'w1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("row");
        assert_eq!(count, 1, "upsert, not duplicate");
        assert_eq!(
            confirmed, 1,
            "operator confirmation survives a machine re-pass"
        );
        assert_eq!(at, 200, "labeled_at refreshed");
    }

    #[test]
    fn post_hoc_stamps_collapse_and_label_within_horizon() {
        let conn = labels_db();
        seed_window(&conn, "w15", 900, T, None, None);
        // 5-min collapse window starting 60s after w15 closes.
        seed_window(&conn, "v5", 300, T + 360, Some(1), Some("agent_loop"));
        let stamped = post_hoc_label_pass(&conn, 1800, T + 1801).expect("pass");
        assert_eq!(stamped, 1, "only w15 is ripe (v5's horizon is not)");
        let c30: i64 = conn
            .query_row(
                "SELECT collapse_30m FROM idx_babel_windows WHERE id='w15'",
                [],
                |r| r.get(0),
            )
            .expect("row");
        assert_eq!(c30, 1);
        let label: String = conn
            .query_row(
                "SELECT label FROM idx_babel_labels WHERE window_id='w15'",
                [],
                |r| r.get(0),
            )
            .expect("label row");
        assert_eq!(label, "agent_loop");
    }

    #[test]
    fn post_hoc_stamps_zero_when_horizon_observed_clean() {
        let conn = labels_db();
        seed_window(&conn, "w15", 900, T, None, None);
        let stamped = post_hoc_label_pass(&conn, 1800, T + 1801).expect("pass");
        assert_eq!(stamped, 1);
        let c30: i64 = conn
            .query_row(
                "SELECT collapse_30m FROM idx_babel_windows WHERE id='w15'",
                [],
                |r| r.get(0),
            )
            .expect("row");
        assert_eq!(c30, 0);
        let labels: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_labels", [], |r| r.get(0))
            .expect("count");
        assert_eq!(labels, 0, "clean horizon writes no label row");
    }

    #[test]
    fn post_hoc_leaves_unripe_windows_null() {
        let conn = labels_db();
        seed_window(&conn, "w15", 900, T, None, None);
        let stamped = post_hoc_label_pass(&conn, 1800, T + 900).expect("pass");
        assert_eq!(stamped, 0, "horizon not yet observable");
        let c30: Option<i64> = conn
            .query_row(
                "SELECT collapse_30m FROM idx_babel_windows WHERE id='w15'",
                [],
                |r| r.get(0),
            )
            .expect("row");
        assert!(c30.is_none());
    }
}
