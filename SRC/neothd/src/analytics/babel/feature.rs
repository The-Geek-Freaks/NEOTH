//! Feature extraction algorithms for the seven B_d variables.
//!
//! Every algorithm is labelled "v0 reference" so future versions can be
//! tracked.  Contributors report `algorithm_version` in the federated window
//! so between-algorithm sensitivity analysis is possible.
//!
//! ## Source events (WAL band codes)
//!
//! | Feature | Source events |
//! |---------|---------------|
//! | C_d | 0xC0 MCP_TOOL_CALLED, 0xFC AGENT_DISPATCHED |
//! | K_d | 0x20 LLM_REQUEST, 0x21 LLM_RESPONSE (output embedding) |
//! | M_d | 0x20 context_used_ratio, 0x47 vram_pct, 0x2F budget cap/total |
//! | A_d | 0xFC AGENT_DISPATCHED (distinct agent_id values) |
//! | V_d | local_load::tokens_per_sec() / V_MAX from norm table |
//! | D_d | tool schema conflict events (0xC1) and role-schema embedding divergence |
//! | H_d | fallback_attempt / fallback_result events in the window |
//!
//! ## Algorithm versions
//!
//! - `C_d_v0`: bipartite density |edges| / (|agents| * |tools|).
//!   When only one agent, C_d = distinct_tools_called / total_tools_available.
//! - `K_d_v0`: mean pairwise cosine similarity of last N output-token-frequency
//!   histograms (no external embedding model; uses in-process token-freq
//!   approximation as a v0 proxy — BLEU-2 fallback documented).
//! - `M_d_v0`: max(context_used_ratio, vram_pct/100, budget_consumed_ratio).
//! - `A_d_v0`: distinct AGENT_DISPATCHED agent_id count, normalised by
//!   AutonomyLevel scalar (Strict=1, Standard=2, Elevated=3, Full=4).
//! - `V_d_v0`: tokens_per_sec / V_MAX (p99 from norm table; cold-start default
//!   150.0 tps), clamped [0, 1].
//! - `D_d_v0`: binary 0/1 flag "any tool schema conflict in window" as v0 proxy
//!   (full Jensen–Shannon divergence over tool-schema token distributions deferred
//!   to v1).
//! - `H_d_v0`: count(distinct successful fallback routes in window) /
//!   (count(distinct sole-path endpoints) + 1).  Defaults to 1.0 when no
//!   fallbacks were attempted (neutral: no observed absence of redundancy).

use serde::{Deserialize, Serialize};

/// All seven normalised features for one window, all in [0,1] for C,K,M,A,V,D
/// and (0,1] for D,H (schema enforces exclusiveMinimum:0 on D and H).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BabelFeatures {
    /// C_d: tool/agent coupling density [0,1].
    pub c: f64,
    /// K_d: semantic convergence pressure [0,1].
    pub k: f64,
    /// M_d: resource/context pressure [0,1].
    pub m: f64,
    /// A_d: autonomous agent density [0,1].
    pub a: f64,
    /// V_d: information velocity [0,1].
    pub v: f64,
    /// D_d: differentiation capacity (0,1].
    pub d: f64,
    /// H_d: heterarchy / redundancy (0,1].
    pub h: f64,
    /// Algorithm version string for each feature — allows sensitivity analysis
    /// across contributors using different extraction methods.
    pub algorithm_versions: FeatureAlgorithmVersions,
}

/// One version tag per feature so sensitivity analysis across contributors is
/// possible even when two instances report the same feature letter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureAlgorithmVersions {
    pub c: String,
    pub k: String,
    pub m: String,
    pub a: String,
    pub v: String,
    pub d: String,
    pub h: String,
}

impl Default for FeatureAlgorithmVersions {
    fn default() -> Self {
        Self {
            c: "C_d_v0".into(),
            k: "K_d_v0".into(),
            m: "M_d_v0".into(),
            a: "A_d_v0".into(),
            v: "V_d_v0".into(),
            d: "D_d_v0".into(),
            h: "H_d_v0".into(),
        }
    }
}

impl BabelFeatures {
    /// Clamp D and H to the minimum representable positive float so the
    /// denominator in the multiplicative score is never zero.  The log form
    /// never has a zero-denominator problem because it rejects D=0 / H=0
    /// before taking the log.
    pub fn clamp_denominators(&self) -> Self {
        let min_positive = 1e-9_f64;
        Self {
            d: self.d.max(min_positive),
            h: self.h.max(min_positive),
            ..self.clone()
        }
    }

    /// Validate that all features are finite and within their documented ranges.
    /// Returns the first field name that fails, or Ok(()).
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.c.is_finite() || self.c < 0.0 { return Err("C"); }
        if !self.k.is_finite() || self.k < 0.0 { return Err("K"); }
        if !self.m.is_finite() || self.m < 0.0 { return Err("M"); }
        if !self.a.is_finite() || self.a < 0.0 { return Err("A"); }
        if !self.v.is_finite() || self.v < 0.0 { return Err("V"); }
        if !self.d.is_finite() || self.d <= 0.0 { return Err("D"); }
        if !self.h.is_finite() || self.h <= 0.0 { return Err("H"); }
        Ok(())
    }
}

/// Accumulator built incrementally as WAL events arrive.
/// Finalised at window close via `BabelFeatureAccumulator::finish`.
#[derive(Clone, Debug, Default)]
pub struct BabelFeatureAccumulator {
    // C_d: bipartite coupling
    pub distinct_agents: std::collections::HashSet<String>,
    pub distinct_tools: std::collections::HashSet<String>,
    pub tool_agent_edges: std::collections::HashSet<(String, String)>,
    pub total_tools_available: usize,

    // K_d: convergence pressure — v0 uses token-freq histogram vectors
    // stored as (token_hash → count) maps, one per response.
    pub output_histograms: Vec<std::collections::HashMap<u32, u32>>,

    // M_d: resource pressure
    pub max_context_used_ratio: f64,
    pub max_vram_pct: f64,
    pub max_budget_consumed_ratio: f64,

    // A_d: agent density
    pub agent_dispatch_ids: std::collections::HashSet<String>,
    pub autonomy_scalar: u8, // 1..4 from AutonomyLevel

    // V_d: velocity (read from local_load at finalise time)
    pub v_max_tps: f64,

    // D_d: differentiation — v0: any schema conflict detected?
    pub schema_conflict_count: u32,

    // H_d: heterarchy
    pub fallback_attempt_routes: std::collections::HashSet<String>,
    pub fallback_success_routes: std::collections::HashSet<String>,
    pub sole_path_endpoints: std::collections::HashSet<String>,
}

impl BabelFeatureAccumulator {
    pub fn new(autonomy_scalar: u8, v_max_tps: f64, total_tools_available: usize) -> Self {
        Self {
            autonomy_scalar: autonomy_scalar.clamp(1, 4),
            v_max_tps: if v_max_tps > 0.0 { v_max_tps } else { 150.0 },
            total_tools_available,
            ..Default::default()
        }
    }

    /// Convert accumulated state into normalised BabelFeatures.
    /// Returns None if the window has insufficient data (< MIN_EVENTS).
    pub fn finish(&self, current_tps: f64) -> Option<BabelFeatures> {
        // C_d_v0
        let c = self.coupling_density();
        // K_d_v0
        let k = self.convergence_pressure();
        // M_d_v0
        let m = (self.max_context_used_ratio
            .max(self.max_vram_pct / 100.0)
            .max(self.max_budget_consumed_ratio))
            .clamp(0.0, 1.0);
        // A_d_v0
        let a = self.agent_density();
        // V_d_v0
        let v = (current_tps / self.v_max_tps).clamp(0.0, 1.0);
        // D_d_v0
        let d = if self.schema_conflict_count > 0 { 0.3_f64 } else { 1.0_f64 };
        // H_d_v0
        let h = self.heterarchy();

        let f = BabelFeatures {
            c, k, m, a, v, d, h,
            algorithm_versions: FeatureAlgorithmVersions::default(),
        };
        if f.validate().is_err() { return None; }
        Some(f)
    }

    fn coupling_density(&self) -> f64 {
        let n_agents = self.distinct_agents.len();
        let n_tools = self.distinct_tools.len();
        if n_agents == 0 || n_tools == 0 { return 0.0; }
        if n_agents == 1 {
            // Single-agent: fraction of available tools called
            let denom = self.total_tools_available.max(1);
            return (self.distinct_tools.len() as f64 / denom as f64).clamp(0.0, 1.0);
        }
        let max_edges = (n_agents * n_tools) as f64;
        (self.tool_agent_edges.len() as f64 / max_edges).clamp(0.0, 1.0)
    }

    fn convergence_pressure(&self) -> f64 {
        // K_d_v0: mean pairwise cosine similarity of output histograms.
        // Returns 0.0 (maximum diversity) when fewer than 3 outputs available.
        let hists = &self.output_histograms;
        if hists.len() < 3 { return 0.0; }
        let mut total_sim = 0.0_f64;
        let mut count = 0usize;
        for i in 0..hists.len() {
            for j in (i + 1)..hists.len() {
                total_sim += cosine_similarity_histograms(&hists[i], &hists[j]);
                count += 1;
            }
        }
        if count == 0 { return 0.0; }
        (total_sim / count as f64).clamp(0.0, 1.0)
    }

    fn agent_density(&self) -> f64 {
        let raw = self.agent_dispatch_ids.len() as f64;
        let scaled = raw / self.autonomy_scalar as f64;
        // Normalise against a soft ceiling of 8 agents per autonomy unit
        (scaled / 8.0).clamp(0.0, 1.0)
    }

    fn heterarchy(&self) -> f64 {
        // H_d_v0: successful distinct fallback routes / (sole-path endpoints + 1)
        let successes = self.fallback_success_routes.len();
        let sole_paths = self.sole_path_endpoints.len();
        if self.fallback_attempt_routes.is_empty() {
            // No fallbacks attempted → structural default: 1.0 (neutral)
            return 1.0;
        }
        ((successes as f64) / (sole_paths as f64 + 1.0)).clamp(1e-9, 1.0)
    }
}

/// Cosine similarity between two token-frequency histograms represented as
/// sparse maps (token_hash → count).  O(min(|a|, |b|)) via dot-product of
/// the smaller map against the larger.
fn cosine_similarity_histograms(
    a: &std::collections::HashMap<u32, u32>,
    b: &std::collections::HashMap<u32, u32>,
) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    let dot: f64 = a.iter()
        .filter_map(|(k, &va)| b.get(k).map(|&vb| va as f64 * vb as f64))
        .sum();
    let norm_a: f64 = a.values().map(|&v| (v as f64).powi(2)).sum::<f64>().sqrt();
    let norm_b: f64 = b.values().map(|&v| (v as f64).powi(2)).sum::<f64>().sqrt();
    let denom = norm_a * norm_b;
    if denom == 0.0 { 0.0 } else { (dot / denom).clamp(0.0, 1.0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_validate_rejects_zero_d_and_h() {
        let bad = BabelFeatures {
            c: 0.5, k: 0.5, m: 0.5, a: 0.5, v: 0.5,
            d: 0.0, // violates exclusiveMinimum: 0
            h: 0.5,
            algorithm_versions: FeatureAlgorithmVersions::default(),
        };
        assert_eq!(bad.validate(), Err("D"));
    }

    #[test]
    fn clamp_denominators_ensures_d_h_positive() {
        let f = BabelFeatures {
            c: 0.1, k: 0.1, m: 0.1, a: 0.1, v: 0.1,
            d: 0.0, h: 0.0,
            algorithm_versions: FeatureAlgorithmVersions::default(),
        };
        let clamped = f.clamp_denominators();
        assert!(clamped.d > 0.0);
        assert!(clamped.h > 0.0);
    }

    #[test]
    fn single_agent_coupling_uses_tool_fraction() {
        let mut acc = BabelFeatureAccumulator::new(2, 150.0, 10);
        acc.distinct_agents.insert("agent_a".into());
        acc.distinct_tools.insert("tool_1".into());
        acc.distinct_tools.insert("tool_2".into());
        // 2 of 10 tools → 0.2
        let c = acc.coupling_density();
        assert!((c - 0.2).abs() < 1e-9);
    }

    #[test]
    fn convergence_pressure_zero_for_fewer_than_three_outputs() {
        let acc = BabelFeatureAccumulator::new(2, 150.0, 4);
        assert_eq!(acc.convergence_pressure(), 0.0);
    }

    #[test]
    fn identical_histograms_give_max_convergence() {
        let mut acc = BabelFeatureAccumulator::new(2, 150.0, 4);
        let hist: std::collections::HashMap<u32, u32> = [(1, 5), (2, 3)].into();
        acc.output_histograms.push(hist.clone());
        acc.output_histograms.push(hist.clone());
        acc.output_histograms.push(hist);
        assert!((acc.convergence_pressure() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn heterarchy_defaults_to_one_when_no_fallbacks_attempted() {
        let acc = BabelFeatureAccumulator::new(2, 150.0, 4);
        assert_eq!(acc.heterarchy(), 1.0);
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors_is_zero() {
        let a: std::collections::HashMap<u32, u32> = [(1, 1)].into();
        let b: std::collections::HashMap<u32, u32> = [(2, 1)].into();
        assert_eq!(cosine_similarity_histograms(&a, &b), 0.0);
    }
}
