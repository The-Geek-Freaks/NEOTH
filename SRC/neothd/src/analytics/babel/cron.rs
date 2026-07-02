//! GOLD-DELTA-03 — Babel cron tick logic.
//!
//! Pure, synchronous window bookkeeping: the daemon loop (GOLD-DELTA-04)
//! scans the WAL, maps frames into content-free [`WalEventRecord`]s and
//! calls [`BabelCronState::tick`]. The tick
//!
//! 1. ingests every event into all four granularity accumulators,
//! 2. closes any window whose deadline has passed (rolling forward across
//!    missed boundaries — a slow tick only delays close detection),
//! 3. computes [`BabelScores`] + collapse detection for each closed window,
//! 4. persists the window to `idx_babel_windows` (SQLite only — the WAL
//!    event byte space is exhausted, 255/256),
//! 5. checks the operator threshold on the 15-minute window and returns
//!    [`CronEvent`]s for the daemon to log / fan out over SSE.
//!
//! Content discipline: `WalEventRecord` carries derived metrics ONLY —
//! token histograms, ratios, ids — never prompt or response text.

use std::collections::HashMap;

use anyhow::Result;
use rusqlite::Connection;

use super::collapse::{detect_collapse, CollapseEventRecord, CollapseEventType};
use super::config::BabelConfig;
use super::feature::BabelFeatureAccumulator;
use super::norm::Normaliser;
use super::score::BabelScores;
use super::store;
use super::window::{BabelWindow, WindowAccumulator, WindowGranularity};

/// One content-free event derived from a WAL frame. The daemon layer owns
/// the WAL-code → variant mapping; this module only consumes the result.
#[derive(Clone, Debug)]
pub struct WalEventRecord {
    pub ts_unix: i64,
    pub kind: WalEventKind,
}

/// Derived-metrics-only event kinds feeding the seven B_d variables and the
/// collapse detectors (see the source-event table in `feature.rs`).
#[derive(Clone, Debug)]
pub enum WalEventKind {
    /// 0xC0 MCP_TOOL_CALLED — feeds C_d coupling. `agent_id = None` means
    /// the operator's own session (counted as one implicit agent).
    McpToolCalled { tool: String, agent_id: Option<String> },
    /// 0xFC AGENT_DISPATCHED — feeds A_d density + C_d agent set.
    AgentDispatched { agent_id: String },
    /// 0x21 LLM_RESPONSE — feeds K_d (histogram), V_d (tokens), M_d (ratio).
    LlmResponse {
        output_tokens: u32,
        token_histogram: HashMap<u32, u32>,
        context_used_ratio: Option<f64>,
    },
    /// 0x47 vram / 0x2F budget snapshots — feeds M_d.
    ResourceSnapshot { vram_pct: Option<f64>, budget_consumed_ratio: Option<f64> },
    /// Context-window boundary report — feeds M_d + context_limit_failure.
    ContextBoundary { context_used_ratio: f64 },
    /// 0xC1 tool schema conflict — feeds D_d.
    SchemaConflict,
    /// Fallback routing attempt — feeds H_d + fallback_failure.
    FallbackAttempt { route: String },
    /// Fallback routing outcome — feeds H_d + fallback_failure.
    FallbackResult { route: String, success: bool },
    /// Endpoint known to have no redundant route — feeds H_d denominator.
    SolePathEndpoint { endpoint: String },
    /// Retry of a (tool, agent) pair — feeds agent_loop / retry_storm.
    Retry { tool: Option<String>, agent_id: Option<String> },
    /// Tool call timed out — feeds tool_timeout_cascade.
    ToolTimeout { tool: Option<String> },
    /// Tool call errored — feeds tool_timeout_cascade (timeout error_kind).
    ToolError { tool: Option<String>, error_kind: Option<String> },
    /// Inference finished (possibly with an error) — feeds
    /// context_limit_failure.
    InferenceEnd { error_kind: Option<String> },
    /// Operator labelled this span a failure — feeds objective_failure.
    OperatorLabel,
}

/// What a tick produced — the daemon logs / fans these out.
#[derive(Clone, Debug)]
pub enum CronEvent {
    /// A window closed and its row was persisted.
    WindowComputed(Box<BabelWindow>),
    /// The 15-minute window's normalised B_d crossed the operator threshold.
    ThresholdBreached { window_id: String, score: f64, threshold: f64 },
}

/// Per-granularity in-flight window state. Only the collapse-relevant
/// projection of each event is retained (feature data folds into the
/// accumulator immediately) — a full event log would clone every LLM
/// token histogram for nothing.
struct GranState {
    meta: WindowAccumulator,
    features: BabelFeatureAccumulator,
    collapse_events: Vec<CollapseEventRecord>,
    token_sum: u64,
}

impl GranState {
    fn new(
        granularity: WindowGranularity,
        ts_start: i64,
        autonomy_scalar: u8,
        v_max: f64,
        tools: usize,
    ) -> Self {
        Self {
            meta: WindowAccumulator::new(granularity, ts_start),
            features: BabelFeatureAccumulator::new(autonomy_scalar, v_max, tools),
            collapse_events: Vec::new(),
            token_sum: 0,
        }
    }
}

/// The cron's rolling state: four parallel window accumulators plus the
/// scoring context (normaliser, frozen epsilon, threshold).
pub struct BabelCronState {
    session_id_pseudo: String,
    autonomy_scalar: u8,
    v_max: f64,
    threshold: f64,
    epsilon: Option<f64>,
    mcp_tool_count: usize,
    normaliser: Normaliser,
    /// K_d of the last 3 closed 5-min windows — the semantic_degradation
    /// detector's sub-window series. ponytail: stale K values survive empty
    /// 5-min windows; acceptable for v0 (detector needs 3 consecutive highs).
    recent_k5: Vec<f64>,
    grans: Vec<GranState>,
}

impl BabelCronState {
    pub fn new(
        cfg: &BabelConfig,
        session_id_pseudo: String,
        autonomy_scalar: u8,
        now: i64,
        mcp_tool_count: usize,
    ) -> Self {
        debug_assert_eq!(
            WindowGranularity::all()[0],
            WindowGranularity::FiveMin,
            "FiveMin must be index 0: the recent_k5 ring depends on 5-min \
             windows closing before larger windows at a shared boundary"
        );
        let grans = WindowGranularity::all()
            .iter()
            .map(|&g| GranState::new(g, now, autonomy_scalar, cfg.v_max_default, mcp_tool_count))
            .collect();
        Self {
            session_id_pseudo,
            autonomy_scalar,
            v_max: cfg.v_max_default,
            threshold: cfg.threshold,
            epsilon: cfg.epsilon_calibrated,
            mcp_tool_count,
            normaliser: Normaliser::cold_start(),
            recent_k5: Vec::new(),
            grans,
        }
    }

    /// Swap in fresh normalisation parameters (GOLD-DELTA-05 sweep).
    pub fn set_normaliser(&mut self, n: Normaliser) {
        self.normaliser = n;
    }

    /// Freeze the calibrated epsilon (GOLD-DELTA-06); b_mult starts emitting
    /// on the next window close.
    pub fn set_epsilon(&mut self, epsilon: f64) {
        self.epsilon = Some(epsilon);
    }

    /// Ingest new WAL-derived events, close every expired window, persist
    /// closed windows and return what happened. Events may arrive unsorted;
    /// late events from before the current window start are attributed to
    /// the current window (the daemon's scan cursor bounds the skew).
    pub fn tick(
        &mut self,
        now: i64,
        mut events: Vec<WalEventRecord>,
        mcp_tool_count: usize,
        conn: &Connection,
    ) -> Result<Vec<CronEvent>> {
        self.mcp_tool_count = mcp_tool_count;
        events.sort_by_key(|e| e.ts_unix);
        let mut out = Vec::new();
        for ev in &events {
            // Granularity order matters: FiveMin (idx 0) must close before
            // FifteenMin at a shared boundary so the K_d sub-window ring is
            // current when the 15-min collapse detector runs.
            for idx in 0..self.grans.len() {
                while self.grans[idx].meta.is_expired(ev.ts_unix) {
                    self.close_one(idx, conn, &mut out)?;
                }
                ingest(&mut self.grans[idx], ev);
            }
        }
        for idx in 0..self.grans.len() {
            while self.grans[idx].meta.is_expired(now) {
                self.close_one(idx, conn, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Close the window at `idx` at its deadline and roll the accumulator
    /// forward one granularity period. Empty windows roll without a row.
    fn close_one(&mut self, idx: usize, conn: &Connection, out: &mut Vec<CronEvent>) -> Result<()> {
        let g = self.grans[idx].meta.granularity;
        let close_ts = self.grans[idx].meta.deadline();
        let old = std::mem::replace(
            &mut self.grans[idx],
            GranState::new(g, close_ts, self.autonomy_scalar, self.v_max, self.mcp_tool_count),
        );
        if old.meta.event_count == 0 {
            return Ok(());
        }
        let tps = old.token_sum as f64 / g.secs() as f64;
        let Some(features) = old.features.finish(tps) else {
            // A dropped window is data loss, not a debug curiosity.
            tracing::warn!(window_secs = g.secs(), "babel window features failed validation, dropped");
            return Ok(());
        };
        let scores = BabelScores::compute(&features, &self.normaliser, self.epsilon);
        // 5-min windows ARE the sub-window series — they get no series of
        // their own; larger windows read the ring of recent 5-min K values.
        let k_series: &[f64] = if g == WindowGranularity::FiveMin { &[] } else { &self.recent_k5 };
        let collapse = detect_collapse(&old.collapse_events, k_series);
        if g == WindowGranularity::FiveMin {
            self.recent_k5.push(features.k);
            if self.recent_k5.len() > 3 {
                self.recent_k5.remove(0);
            }
        }
        let av = features.algorithm_versions.clone();
        let window = BabelWindow {
            id: uuid::Uuid::now_v7().to_string(),
            session_id_pseudo: self.session_id_pseudo.clone(),
            granularity: g,
            ts_start: old.meta.ts_start,
            ts_end: close_ts,
            features,
            scores,
            collapse,
            schema_version: BabelWindow::SCHEMA_VERSION.to_string(),
            algorithm_version_c: av.c,
            algorithm_version_k: av.k,
            algorithm_version_m: av.m,
            algorithm_version_a: av.a,
            algorithm_version_v: av.v,
            algorithm_version_d: av.d,
            algorithm_version_h: av.h,
        };
        store::insert_window(conn, &window)?;
        if g == WindowGranularity::FifteenMin {
            if let Some(b_mult) = window.scores.b_mult {
                if b_mult >= self.threshold {
                    out.push(CronEvent::ThresholdBreached {
                        window_id: window.id.clone(),
                        score: b_mult,
                        threshold: self.threshold,
                    });
                }
            }
        }
        out.push(CronEvent::WindowComputed(Box::new(window)));
        Ok(())
    }
}

/// Feed one event into a granularity's feature accumulator + event log.
fn ingest(gran: &mut GranState, ev: &WalEventRecord) {
    gran.meta.event_count += 1;
    match &ev.kind {
        WalEventKind::McpToolCalled { tool, agent_id } => {
            let agent = agent_id.clone().unwrap_or_else(|| "operator".to_string());
            gran.features.distinct_agents.insert(agent.clone());
            gran.features.distinct_tools.insert(tool.clone());
            gran.features.tool_agent_edges.insert((agent, tool.clone()));
        }
        WalEventKind::AgentDispatched { agent_id } => {
            gran.features.distinct_agents.insert(agent_id.clone());
            gran.features.agent_dispatch_ids.insert(agent_id.clone());
        }
        WalEventKind::LlmResponse { output_tokens, token_histogram, context_used_ratio } => {
            if !token_histogram.is_empty() {
                gran.features.output_histograms.push(token_histogram.clone());
            }
            gran.token_sum += u64::from(*output_tokens);
            if let Some(r) = context_used_ratio {
                gran.features.max_context_used_ratio = gran.features.max_context_used_ratio.max(*r);
            }
        }
        WalEventKind::ResourceSnapshot { vram_pct, budget_consumed_ratio } => {
            if let Some(v) = vram_pct {
                gran.features.max_vram_pct = gran.features.max_vram_pct.max(*v);
            }
            if let Some(b) = budget_consumed_ratio {
                gran.features.max_budget_consumed_ratio =
                    gran.features.max_budget_consumed_ratio.max(*b);
            }
        }
        WalEventKind::ContextBoundary { context_used_ratio } => {
            gran.features.max_context_used_ratio =
                gran.features.max_context_used_ratio.max(*context_used_ratio);
        }
        WalEventKind::SchemaConflict => {
            gran.features.schema_conflict_count += 1;
        }
        WalEventKind::FallbackAttempt { route } => {
            gran.features.fallback_attempt_routes.insert(route.clone());
        }
        WalEventKind::FallbackResult { route, success } => {
            if *success {
                gran.features.fallback_success_routes.insert(route.clone());
            }
        }
        WalEventKind::SolePathEndpoint { endpoint } => {
            gran.features.sole_path_endpoints.insert(endpoint.clone());
        }
        // Collapse-only kinds: no feature contribution.
        WalEventKind::Retry { .. }
        | WalEventKind::ToolTimeout { .. }
        | WalEventKind::ToolError { .. }
        | WalEventKind::InferenceEnd { .. }
        | WalEventKind::OperatorLabel => {}
    }
    if let Some(rec) = to_collapse_record(ev) {
        gran.collapse_events.push(rec);
    }
}

/// Map a WAL-derived event onto the collapse detector's record shape.
/// Feature-only kinds return None.
fn to_collapse_record(ev: &WalEventRecord) -> Option<CollapseEventRecord> {
    let mut rec = CollapseEventRecord {
        ts_unix: ev.ts_unix,
        event_type: CollapseEventType::Retry, // placeholder, always overwritten
        agent_id: None,
        tool: None,
        success: None,
        error_kind: None,
        context_used_ratio: None,
    };
    match &ev.kind {
        WalEventKind::Retry { tool, agent_id } => {
            rec.event_type = CollapseEventType::Retry;
            rec.tool = tool.clone();
            rec.agent_id = agent_id.clone();
        }
        WalEventKind::ToolTimeout { tool } => {
            rec.event_type = CollapseEventType::ToolTimeout;
            rec.tool = tool.clone();
        }
        WalEventKind::ToolError { tool, error_kind } => {
            rec.event_type = CollapseEventType::ToolError;
            rec.tool = tool.clone();
            rec.error_kind = error_kind.clone();
        }
        WalEventKind::ContextBoundary { context_used_ratio } => {
            rec.event_type = CollapseEventType::ContextBoundary;
            rec.context_used_ratio = Some(*context_used_ratio);
        }
        WalEventKind::FallbackAttempt { route } => {
            rec.event_type = CollapseEventType::FallbackAttempt;
            rec.tool = Some(route.clone());
        }
        WalEventKind::FallbackResult { route, success } => {
            rec.event_type = CollapseEventType::FallbackResult;
            rec.tool = Some(route.clone());
            rec.success = Some(*success);
        }
        WalEventKind::InferenceEnd { error_kind } => {
            rec.event_type = CollapseEventType::InferenceEnd;
            rec.error_kind = error_kind.clone();
        }
        WalEventKind::OperatorLabel => {
            rec.event_type = CollapseEventType::OperatorLabel;
        }
        WalEventKind::McpToolCalled { .. }
        | WalEventKind::AgentDispatched { .. }
        | WalEventKind::LlmResponse { .. }
        | WalEventKind::ResourceSnapshot { .. }
        | WalEventKind::SchemaConflict
        | WalEventKind::SolePathEndpoint { .. } => return None,
    }
    Some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::babel::store::ensure_schema;

    const BASE: i64 = 1_800_000_000;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        conn
    }

    fn state(cfg: &BabelConfig) -> BabelCronState {
        BabelCronState::new(cfg, "a1b2c3d4e5f60718".into(), 2, BASE, 4)
    }

    fn llm_response(ts: i64) -> WalEventRecord {
        let hist: HashMap<u32, u32> = [(1, 5), (2, 3)].into();
        WalEventRecord {
            ts_unix: ts,
            kind: WalEventKind::LlmResponse {
                output_tokens: 100,
                token_histogram: hist,
                context_used_ratio: Some(0.5),
            },
        }
    }

    /// Agent dispatch + tool call + 3 LLM responses — every numerator
    /// variable strictly positive so b_log is defined.
    fn active_burst(t0: i64) -> Vec<WalEventRecord> {
        vec![
            WalEventRecord {
                ts_unix: t0 + 10,
                kind: WalEventKind::AgentDispatched { agent_id: "agent_a".into() },
            },
            WalEventRecord {
                ts_unix: t0 + 20,
                kind: WalEventKind::McpToolCalled {
                    tool: "bash".into(),
                    agent_id: Some("agent_a".into()),
                },
            },
            llm_response(t0 + 30),
            llm_response(t0 + 60),
            llm_response(t0 + 90),
        ]
    }

    #[test]
    fn window_computed_with_finite_b_log_after_boundary() {
        let conn = mem_db();
        let mut st = state(&BabelConfig::default());
        let out = st.tick(BASE + 301, active_burst(BASE), 4, &conn).expect("tick");
        let computed: Vec<_> = out
            .iter()
            .filter_map(|e| match e {
                CronEvent::WindowComputed(w) => Some(w),
                _ => None,
            })
            .collect();
        assert_eq!(computed.len(), 1, "exactly the 5-min window closed");
        let w = computed[0];
        assert_eq!(w.granularity, WindowGranularity::FiveMin);
        assert_eq!(w.ts_start, BASE);
        assert_eq!(w.ts_end, BASE + 300);
        let b_log = w.scores.b_log.expect("all numerators positive");
        assert!(b_log.is_finite());
    }

    #[test]
    fn window_row_persisted_in_sqlite() {
        let conn = mem_db();
        let mut st = state(&BabelConfig::default());
        st.tick(BASE + 301, active_burst(BASE), 4, &conn).expect("tick");
        let (count, secs, variables): (i64, i64, String) = conn
            .query_row(
                "SELECT COUNT(*), MAX(window_secs), MAX(variables) FROM idx_babel_windows",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("select");
        assert_eq!(count, 1);
        assert_eq!(secs, 300);
        let vars: serde_json::Value = serde_json::from_str(&variables).expect("valid JSON");
        assert!(vars["C"].is_number(), "raw features present");
        assert_eq!(vars["algo"]["k"], "K_d_v0", "algorithm versions persisted per-row");
        assert_eq!(vars["schema"], BabelWindow::SCHEMA_VERSION);
    }

    #[test]
    fn empty_window_rolls_without_persist() {
        let conn = mem_db();
        let mut st = state(&BabelConfig::default());
        let out = st.tick(BASE + 400, Vec::new(), 4, &conn).expect("tick");
        assert!(out.is_empty(), "no events → no rows, no cron events");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))
            .expect("select");
        assert_eq!(count, 0);
    }

    #[test]
    fn fifteen_min_threshold_breach_emitted() {
        let conn = mem_db();
        let cfg = BabelConfig {
            threshold: 0.0, // any emitted b_mult crosses
            epsilon_calibrated: Some(0.01),
            ..BabelConfig::default()
        };
        let mut st = state(&cfg);
        let out = st.tick(BASE + 901, active_burst(BASE), 4, &conn).expect("tick");
        let breach = out.iter().find(|e| matches!(e, CronEvent::ThresholdBreached { .. }));
        let Some(CronEvent::ThresholdBreached { score, threshold, .. }) = breach else {
            panic!("expected a threshold breach on the 15-min window close");
        };
        assert!(score.is_finite());
        assert_eq!(*threshold, 0.0);
        // 5-min window with events + 15-min window; empty 5-min rolls skipped.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))
            .expect("select");
        assert_eq!(count, 2);
    }

    #[test]
    fn events_after_boundary_land_in_next_window() {
        let conn = mem_db();
        let mut st = state(&BabelConfig::default());
        let tool_call = |ts: i64| WalEventRecord {
            ts_unix: ts,
            kind: WalEventKind::McpToolCalled { tool: "bash".into(), agent_id: None },
        };
        st.tick(BASE + 601, vec![tool_call(BASE + 30), tool_call(BASE + 350)], 4, &conn)
            .expect("tick");
        let mut stmt = conn
            .prepare(
                "SELECT ts_start FROM idx_babel_windows WHERE window_secs = 300 ORDER BY ts_start",
            )
            .expect("prepare");
        let starts: Vec<i64> = stmt
            .query_map([], |r| r.get(0))
            .expect("query")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("rows");
        assert_eq!(
            starts,
            vec![BASE, BASE + 300],
            "one row per 5-min window, event split across the boundary"
        );
    }
}
