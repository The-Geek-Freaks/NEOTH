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

use serde::{Deserialize, Serialize};

/// The 7 canonical collapse labels, matching the enum in the JSON schema.
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
        }
    }
}

/// Output of the collapse label detector for one window.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollapseDetection {
    /// Whether any collapse label fired in the prediction horizon.
    pub collapse_within_5m: bool,
    pub collapse_within_30m: Option<bool>,
    pub collapse_at_next_task: Option<bool>,
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
        collapse_within_30m: None,   // populated by the 30m window aggregator
        collapse_at_next_task: None, // populated by the export pipeline
        collapse_kind: kind,
        negative_control: false,
        negative_control_type: None,
    }
}

// ── Individual detectors ─────────────────────────────────────────────────────

/// agent_loop: identical (tool, agent_id) retry tuple ≥3 times within 60s.
fn detect_agent_loop(events: &[CollapseEventRecord]) -> Option<i64> {
    let retries: Vec<_> = events.iter()
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
    let mut retry_ts: Vec<i64> = events.iter()
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
    let timeout_tools: std::collections::HashSet<_> = events.iter()
        .filter(|e| {
            e.event_type == CollapseEventType::ToolTimeout
                || (e.event_type == CollapseEventType::ToolError
                    && e.error_kind.as_deref().map(|s| s.contains("timeout")).unwrap_or(false))
        })
        .filter_map(|e| e.tool.as_deref())
        .collect();
    if timeout_tools.len() > 3 {
        // Return timestamp of the 4th distinct timeout
        events.iter()
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
        if let Some(ts) = near_limit_ts {
            if (ev.event_type == CollapseEventType::ToolError
                || ev.event_type == CollapseEventType::InferenceEnd)
                && ev.error_kind.as_deref().map(|s| {
                    s.contains("context") || s.contains("truncation")
                }).unwrap_or(false)
            {
                return Some(ts);
            }
        }
    }
    None
}

/// semantic_degradation: K_d > 0.90 for 3 consecutive 5-minute values.
fn detect_semantic_degradation(k_d_series: &[f64]) -> bool {
    if k_d_series.len() < 3 { return false; }
    k_d_series.windows(3).any(|w| w.iter().all(|&k| k > 0.90))
}

/// fallback_failure: fallback_attempt not followed by success=true within 60s.
fn detect_fallback_failure(events: &[CollapseEventRecord]) -> Option<i64> {
    for ev in events.iter().filter(|e| e.event_type == CollapseEventType::FallbackAttempt) {
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
    events.iter()
        .find(|e| e.event_type == CollapseEventType::OperatorLabel)
        .map(|e| e.ts_unix)
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
        let events: Vec<_> = (0..6)
            .map(|i| retry_event(i * 4, "any", "any"))
            .collect();
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
        assert_eq!(CollapseLabel::SemanticDegradation.as_str(), "semantic_degradation");
    }
}
