//! GOLD-HR-02 — the compression orchestrator + the NEOTH gating layer.
//!
//! Two pieces:
//!
//! 1. [`CompressionPipeline`] — content-type-keyed dispatch over reformat then
//!    offload transforms. Ported from headroom's
//!    `transforms/pipeline/orchestrator.rs`, run **sequentially** (NEOTH issues
//!    one block per call — nowhere near the proxy QPS that justified
//!    upstream's `rayon::join`/`par_iter`; correctness is identical either
//!    way). It ALWAYS returns some output — a transform error is recorded as a
//!    skip, never propagated, never panics. On the hot path of every tool-call
//!    response that property is load-bearing.
//!
//! 2. The **gating layer** — [`Gate`] + [`CompressionPipeline::compress_block`].
//!    Before any transform runs, a block must clear three checks driven by
//!    `freedom.yaml::compression`: the master switch is on, the block is past
//!    the **live zone** (the most-recent `live_zone_turns` are never touched —
//!    correctness + provider prompt-cache hits), and it is at least
//!    `min_block_bytes`. Fail any check → byte-identical passthrough.
//!
//! At this slice the transform registry is empty (the per-type compressors are
//! HR-04..07), so an eligible block still round-trips unchanged — the gating,
//! routing and CCR plumbing are what land here.

use std::collections::HashMap;
use std::sync::Arc;

use crate::context::compress::ccr::CcrStore;
use crate::context::compress::content_detector::{detect_content_type, ContentType};
use crate::context::compress::transform::{
    CompressionContext, OffloadTransform, ReformatTransform, TransformError,
};

/// Orchestrator acceptance thresholds. Defaults match headroom's conservative
/// stock config — a wrongly-fired offload costs both latency (retrieval round
/// trip) and accuracy (the model may not retrieve when it should).
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// After reformat, if `output_len/input_len ≤ this`, reformat is treated
    /// as sufficient and offloads are skipped unless bloat demands them.
    pub reformat_target_ratio: f64,
    /// Bloat score at or above which an offload runs regardless of reformat.
    pub bloat_threshold: f32,
    /// After reformat, if `output_len/input_len > this`, run offloads even
    /// below the bloat threshold (the "reformat barely helped" fallback).
    pub offload_fallback_ratio: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            reformat_target_ratio: 0.5,
            bloat_threshold: 0.5,
            offload_fallback_ratio: 0.85,
        }
    }
}

/// Result of [`CompressionPipeline::run`] / [`CompressionPipeline::compress_block`].
#[derive(Debug, Clone, Default)]
pub struct PipelineResult {
    /// Final output. Equal to the input when every stage skipped (or the block
    /// was gated out).
    pub output: String,
    /// Total bytes removed across accepted stages.
    pub bytes_saved: usize,
    /// Reformat + offload names actually accepted, in execution order.
    pub steps_applied: Vec<String>,
    /// CCR keys produced by accepted offloads, in step order. Empty when only
    /// reformats ran or nothing ran.
    pub cache_keys: Vec<String>,
    /// Why the block was skipped, when it was gated out (`None` = ran).
    pub skipped: Option<CompressionSkip>,
}

impl PipelineResult {
    /// A byte-identical passthrough result carrying a skip reason.
    fn passthrough(content: &str, reason: CompressionSkip) -> Self {
        Self {
            output: content.to_string(),
            skipped: Some(reason),
            ..Default::default()
        }
    }
}

// ─── Gating layer ──────────────────────────────────────────────────────

/// Why a block was not compressed. Surfaced for telemetry / the WAL
/// `COMPRESSION_APPLIED` frame (HR-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionSkip {
    /// `freedom.yaml::compression.enabled = false`.
    Disabled,
    /// Within the live zone (one of the most-recent `live_zone_turns`).
    LiveZone,
    /// Smaller than `min_block_bytes`.
    TooSmall,
}

/// Runtime view of `freedom.yaml::compression`'s gating knobs. Built by the
/// wiring layer from `config::CompressionConfig`.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    pub enabled: bool,
    pub min_block_bytes: usize,
    pub live_zone_turns: usize,
}

impl Gate {
    /// Permissive gate for tests / always-on call sites.
    pub fn enabled(min_block_bytes: usize, live_zone_turns: usize) -> Self {
        Self {
            enabled: true,
            min_block_bytes,
            live_zone_turns,
        }
    }

    /// A disabled gate — everything passes through untouched.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            min_block_bytes: 0,
            live_zone_turns: 0,
        }
    }

    /// Decide whether a block at `age_from_tail` (0 = newest turn) is eligible.
    /// Order matches the cheapest-check-first principle.
    pub fn check(&self, content: &str, age_from_tail: usize) -> Result<(), CompressionSkip> {
        if !self.enabled {
            return Err(CompressionSkip::Disabled);
        }
        if in_live_zone(age_from_tail, self.live_zone_turns) {
            return Err(CompressionSkip::LiveZone);
        }
        if content.len() < self.min_block_bytes {
            return Err(CompressionSkip::TooSmall);
        }
        Ok(())
    }
}

/// True if a block at `age_from_tail` (0 = newest) sits in the protected live
/// zone of the last `live_zone_turns` turns.
#[inline]
pub fn in_live_zone(age_from_tail: usize, live_zone_turns: usize) -> bool {
    age_from_tail < live_zone_turns
}

/// Rough chars-per-token estimate for the adaptive sizer's budget→bytes
/// conversion. Matches the ≈4-chars/token rule NEOTH uses elsewhere for
/// English + code; intentionally conservative so we never under-target.
pub const BYTES_PER_TOKEN_ESTIMATE: usize = 4;

/// Adaptive sizer: the byte size a compressed block should target to fit a
/// token budget. Offload transforms read this off [`CompressionContext`].
#[inline]
pub fn target_bytes_for_budget(token_budget: usize) -> usize {
    token_budget.saturating_mul(BYTES_PER_TOKEN_ESTIMATE)
}

// ─── Orchestrator ──────────────────────────────────────────────────────

/// Sequential reformat-then-gated-offload pipeline.
pub struct CompressionPipeline {
    reformats_by_type: HashMap<ContentType, Vec<Arc<dyn ReformatTransform>>>,
    offloads_by_type: HashMap<ContentType, Vec<Arc<dyn OffloadTransform>>>,
    thresholds: Thresholds,
}

impl CompressionPipeline {
    pub fn builder() -> CompressionPipelineBuilder {
        CompressionPipelineBuilder::default()
    }

    /// Gate, then compress. The high-level entry the dispatch loop calls per
    /// block (HR-08). Ineligible blocks return a byte-identical passthrough
    /// carrying the [`CompressionSkip`] reason; eligible blocks are routed by
    /// content type through [`run`](Self::run).
    pub fn compress_block(
        &self,
        content: &str,
        age_from_tail: usize,
        gate: &Gate,
        ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> PipelineResult {
        if let Err(reason) = gate.check(content, age_from_tail) {
            return PipelineResult::passthrough(content, reason);
        }
        let content_type = detect_content_type(content).content_type;
        self.run(content, content_type, ctx, store)
    }

    /// Run the pipeline against a block already known to be eligible and of a
    /// known content type. `store` receives offload payloads under their
    /// cache keys; reformat-only runs don't touch it.
    pub fn run(
        &self,
        content: &str,
        content_type: ContentType,
        ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> PipelineResult {
        if content.is_empty() {
            return PipelineResult::default();
        }
        let original_len = content.len();

        let empty_reformats: Vec<Arc<dyn ReformatTransform>> = Vec::new();
        let empty_offloads: Vec<Arc<dyn OffloadTransform>> = Vec::new();
        let reformats = self
            .reformats_by_type
            .get(&content_type)
            .unwrap_or(&empty_reformats);
        let offloads = self
            .offloads_by_type
            .get(&content_type)
            .unwrap_or(&empty_offloads);

        // Phase 1 — reformats (serial, stop-early at target ratio).
        let reformat_acc = self.run_reformats(content, reformats);
        // Phase 2 — bloat estimates (one per offload).
        let bloat_scores: Vec<f32> = offloads.iter().map(|o| o.estimate_bloat(content)).collect();

        let mut steps = reformat_acc.steps;
        let mut total_saved = reformat_acc.bytes_saved;
        let mut current = reformat_acc.output;
        let reformat_ratio = current.len() as f64 / original_len as f64;

        // Phase 3 — gate + run offloads serially (each sees prior output).
        let mut cache_keys: Vec<String> = Vec::new();
        for (offload, score) in offloads.iter().zip(bloat_scores.iter()) {
            let above_threshold = *score >= self.thresholds.bloat_threshold;
            let reformat_underwhelmed =
                reformat_ratio > self.thresholds.offload_fallback_ratio && *score > 0.0;
            if !(above_threshold || reformat_underwhelmed) {
                tracing::trace!(
                    target: "neoth::compress",
                    offload = offload.name(),
                    score,
                    reformat_ratio,
                    "offload skipped: bloat below threshold and reformat sufficient"
                );
                continue;
            }
            match offload.apply(&current, ctx, store) {
                Ok(out) => {
                    if out.bytes_saved == 0 {
                        continue;
                    }
                    total_saved = total_saved.saturating_add(out.bytes_saved);
                    current = out.output;
                    steps.push(offload.name().to_string());
                    cache_keys.push(out.cache_key);
                }
                Err(TransformError::Internal { message, .. }) => {
                    tracing::warn!(
                        target: "neoth::compress",
                        offload = offload.name(),
                        error = %message,
                        "offload internal error"
                    );
                }
                Err(e) => {
                    tracing::trace!(
                        target: "neoth::compress",
                        offload = offload.name(),
                        error = %e,
                        "offload skipped"
                    );
                }
            }
        }

        PipelineResult {
            output: current,
            bytes_saved: total_saved,
            steps_applied: steps,
            cache_keys,
            skipped: None,
        }
    }

    fn run_reformats(
        &self,
        content: &str,
        reformats: &[Arc<dyn ReformatTransform>],
    ) -> ReformatAccumulator {
        let original_len = content.len();
        let mut current = content.to_string();
        let mut total_saved = 0usize;
        let mut steps: Vec<String> = Vec::new();

        for transform in reformats {
            let ratio = current.len() as f64 / original_len.max(1) as f64;
            if ratio <= self.thresholds.reformat_target_ratio {
                break;
            }
            match transform.apply(&current) {
                Ok(out) => {
                    if out.bytes_saved == 0 {
                        continue;
                    }
                    total_saved = total_saved.saturating_add(out.bytes_saved);
                    current = out.output;
                    steps.push(transform.name().to_string());
                }
                Err(TransformError::Internal { message, .. }) => {
                    tracing::warn!(
                        target: "neoth::compress",
                        transform = transform.name(),
                        error = %message,
                        "reformat internal error"
                    );
                }
                Err(e) => {
                    tracing::trace!(
                        target: "neoth::compress",
                        transform = transform.name(),
                        error = %e,
                        "reformat skipped"
                    );
                }
            }
        }

        ReformatAccumulator {
            output: current,
            bytes_saved: total_saved,
            steps,
        }
    }

    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }
}

struct ReformatAccumulator {
    output: String,
    bytes_saved: usize,
    steps: Vec<String>,
}

/// Fluent builder for [`CompressionPipeline`].
#[derive(Default)]
pub struct CompressionPipelineBuilder {
    reformats_by_type: HashMap<ContentType, Vec<Arc<dyn ReformatTransform>>>,
    offloads_by_type: HashMap<ContentType, Vec<Arc<dyn OffloadTransform>>>,
    thresholds: Option<Thresholds>,
}

impl CompressionPipelineBuilder {
    pub fn with_reformat<T: ReformatTransform + 'static>(mut self, transform: T) -> Self {
        let arc: Arc<dyn ReformatTransform> = Arc::new(transform);
        for ct in arc.applies_to().to_vec() {
            self.reformats_by_type.entry(ct).or_default().push(arc.clone());
        }
        self
    }

    pub fn with_offload<T: OffloadTransform + 'static>(mut self, transform: T) -> Self {
        let arc: Arc<dyn OffloadTransform> = Arc::new(transform);
        for ct in arc.applies_to().to_vec() {
            self.offloads_by_type.entry(ct).or_default().push(arc.clone());
        }
        self
    }

    pub fn with_thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = Some(thresholds);
        self
    }

    pub fn build(self) -> CompressionPipeline {
        CompressionPipeline {
            reformats_by_type: self.reformats_by_type,
            offloads_by_type: self.offloads_by_type,
            thresholds: self.thresholds.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::InMemoryCcrStore;
    use crate::context::compress::transform::{OffloadOutput, ReformatOutput};

    fn ctx() -> CompressionContext {
        CompressionContext::default()
    }
    fn store() -> InMemoryCcrStore {
        InMemoryCcrStore::new()
    }

    // ── Adaptive sizer + live-zone helpers ────────────────────────────

    #[test]
    fn target_bytes_scales_with_budget() {
        assert_eq!(target_bytes_for_budget(0), 0);
        assert_eq!(target_bytes_for_budget(1000), 4000);
        assert_eq!(target_bytes_for_budget(usize::MAX), usize::MAX); // saturating
    }

    #[test]
    fn live_zone_protects_the_tail() {
        // live_zone_turns = 3 → ages 0,1,2 protected; 3+ eligible.
        assert!(in_live_zone(0, 3));
        assert!(in_live_zone(2, 3));
        assert!(!in_live_zone(3, 3));
        // live_zone_turns = 0 → nothing protected.
        assert!(!in_live_zone(0, 0));
    }

    // ── Gating ────────────────────────────────────────────────────────

    #[test]
    fn disabled_gate_passes_through_byte_identical() {
        let p = CompressionPipeline::builder().build();
        let s = store();
        let body = "some tool output ".repeat(100);
        let r = p.compress_block(&body, 99, &Gate::disabled(), &ctx(), &s);
        assert_eq!(r.output, body);
        assert_eq!(r.bytes_saved, 0);
        assert_eq!(r.skipped, Some(CompressionSkip::Disabled));
        assert!(r.steps_applied.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn live_zone_block_is_never_compressed() {
        let p = CompressionPipeline::builder().build();
        let s = store();
        let body = "x".repeat(10_000);
        // age 1 with live_zone_turns 3 → protected.
        let r = p.compress_block(&body, 1, &Gate::enabled(0, 3), &ctx(), &s);
        assert_eq!(r.output, body);
        assert_eq!(r.skipped, Some(CompressionSkip::LiveZone));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn too_small_block_passes_through() {
        let p = CompressionPipeline::builder().build();
        let s = store();
        let r = p.compress_block("tiny", 50, &Gate::enabled(512, 3), &ctx(), &s);
        assert_eq!(r.output, "tiny");
        assert_eq!(r.skipped, Some(CompressionSkip::TooSmall));
    }

    #[test]
    fn eligible_block_with_empty_registry_round_trips_unchanged() {
        // HR-02: routing + CCR plumbing land, but no compressors registered
        // yet (HR-04..07), so an eligible block still comes back identical.
        let p = CompressionPipeline::builder().build();
        let s = store();
        let body = "INFO: heartbeat\n".repeat(500);
        let r = p.compress_block(&body, 50, &Gate::enabled(0, 3), &ctx(), &s);
        assert_eq!(r.output, body);
        assert_eq!(r.skipped, None); // it RAN, just had nothing to do
        assert!(r.steps_applied.is_empty());
    }

    // ── Orchestrator ──────────────────────────────────────────────────

    #[test]
    fn empty_pipeline_passes_input_through() {
        let p = CompressionPipeline::builder().build();
        let s = store();
        let r = p.run("hello world", ContentType::PlainText, &ctx(), &s);
        assert_eq!(r.output, "hello world");
        assert_eq!(r.bytes_saved, 0);
        assert!(r.steps_applied.is_empty() && r.cache_keys.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn empty_input_returns_empty_output() {
        let p = CompressionPipeline::builder().build();
        let r = p.run("", ContentType::JsonArray, &ctx(), &store());
        assert!(r.output.is_empty() && r.steps_applied.is_empty());
    }

    // A test offload that always succeeds, score wired in.
    struct TestOffload {
        score: f32,
        name: &'static str,
    }
    impl OffloadTransform for TestOffload {
        fn name(&self) -> &'static str {
            self.name
        }
        fn applies_to(&self) -> &[ContentType] {
            &[ContentType::PlainText]
        }
        fn estimate_bloat(&self, _c: &str) -> f32 {
            self.score
        }
        fn apply(
            &self,
            content: &str,
            _ctx: &CompressionContext,
            store: &dyn CcrStore,
        ) -> Result<OffloadOutput, TransformError> {
            let half = &content[..content.len() / 2];
            let key = format!("test_{}_key", self.name);
            store.put(&key, content);
            Ok(OffloadOutput::from_lengths(content.len(), half.to_string(), key))
        }
        fn confidence(&self) -> f32 {
            0.5
        }
    }

    #[test]
    fn offload_runs_when_bloat_above_threshold() {
        let p = CompressionPipeline::builder()
            .with_offload(TestOffload { score: 0.9, name: "high" })
            .build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert_eq!(r.steps_applied, vec!["high".to_string()]);
        assert_eq!(r.cache_keys.len(), 1);
        assert!(s.get(&r.cache_keys[0]).is_some());
    }

    #[test]
    fn offload_skipped_when_score_zero() {
        let p = CompressionPipeline::builder()
            .with_offload(TestOffload { score: 0.0, name: "low" })
            .build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert!(r.steps_applied.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn offload_runs_as_fallback_when_reformat_underwhelms() {
        // No reformat → ratio 1.0 > 0.85 fallback, score 0.2 > 0 → runs.
        let p = CompressionPipeline::builder()
            .with_offload(TestOffload { score: 0.2, name: "fallback" })
            .build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert_eq!(r.steps_applied, vec!["fallback".to_string()]);
    }

    struct AlwaysInternalError;
    impl OffloadTransform for AlwaysInternalError {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn applies_to(&self) -> &[ContentType] {
            &[ContentType::PlainText]
        }
        fn estimate_bloat(&self, _c: &str) -> f32 {
            0.9
        }
        fn apply(
            &self,
            _c: &str,
            _ctx: &CompressionContext,
            _s: &dyn CcrStore,
        ) -> Result<OffloadOutput, TransformError> {
            Err(TransformError::internal("boom", "by design"))
        }
        fn confidence(&self) -> f32 {
            0.5
        }
    }

    #[test]
    fn offload_internal_error_does_not_panic_and_yields_input() {
        let p = CompressionPipeline::builder().with_offload(AlwaysInternalError).build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert!(r.steps_applied.is_empty());
        assert_eq!(r.output.len(), 100);
        assert_eq!(s.len(), 0);
    }

    struct HalfReformat;
    impl ReformatTransform for HalfReformat {
        fn name(&self) -> &'static str {
            "half"
        }
        fn applies_to(&self) -> &[ContentType] {
            &[ContentType::PlainText]
        }
        fn apply(&self, content: &str) -> Result<ReformatOutput, TransformError> {
            Ok(ReformatOutput::from_lengths(content.len(), content[..content.len() / 2].to_string()))
        }
    }

    #[test]
    fn reformat_runs_and_records_step() {
        let p = CompressionPipeline::builder().with_reformat(HalfReformat).build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert_eq!(r.steps_applied, vec!["half".to_string()]);
        assert_eq!(r.bytes_saved, 50);
        assert!(r.cache_keys.is_empty());
    }

    #[test]
    fn builder_dispatches_by_applies_to() {
        let p = CompressionPipeline::builder()
            .with_offload(TestOffload { score: 0.9, name: "x" })
            .build();
        let s = store();
        // Offload only applies to PlainText — a JsonArray block ignores it.
        let r = p.run(&"y".repeat(100), ContentType::JsonArray, &ctx(), &s);
        assert!(r.steps_applied.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn builder_preserves_registration_order_for_offloads() {
        let p = CompressionPipeline::builder()
            .with_offload(TestOffload { score: 0.9, name: "first" })
            .with_offload(TestOffload { score: 0.9, name: "second" })
            .build();
        let s = store();
        let r = p.run(&"x".repeat(100), ContentType::PlainText, &ctx(), &s);
        assert_eq!(r.steps_applied, vec!["first".to_string(), "second".to_string()]);
    }
}
