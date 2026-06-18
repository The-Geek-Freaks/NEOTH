//! GOLD-HR-02 — the two transform traits every compressor implements.
//!
//! Ported from headroom's `transforms/pipeline/traits.rs`. With CCR
//! ([`super::ccr`]) no transform destroys information — bytes leave the wire
//! but the original is stashed and retrievable. Transforms split by *how* they
//! shrink output:
//!
//! - [`ReformatTransform`] — pack denser without dropping anything (minify
//!   JSON, RLE-dedup a log, strip comments). The surviving bytes are
//!   semantically equivalent; **no CCR needed**.
//! - [`OffloadTransform`] — drop bytes, stash the original via a
//!   [`CcrStore`], emit a retrieval marker. `OffloadOutput::cache_key` is a
//!   required `String` (not `Option`), so the "you must stash" contract is
//!   type-enforced. Carries a cheap [`OffloadTransform::estimate_bloat`] the
//!   orchestrator gates on before paying for a full `apply`.

use crate::context::compress::ccr::CcrStore;
use crate::context::compress::content_detector::ContentType;

/// Errors a transform can return. All three mean "skip this transform, keep
/// going" — the orchestrator never propagates them and never panics.
/// `Internal` surfaces at WARN; the rest at TRACE.
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    /// Couldn't parse the input. Skip.
    #[error("invalid input for {transform}: {message}")]
    InvalidInput {
        transform: &'static str,
        message: String,
    },
    /// Ran cleanly, nothing to do (empty / already minimal). Skip silently.
    #[error("{transform} skipped: {message}")]
    Skipped {
        transform: &'static str,
        message: String,
    },
    /// Internal failure (serializer, store error, logic bug). Surface at WARN.
    #[error("{transform} internal error: {message}")]
    Internal {
        transform: &'static str,
        message: String,
    },
}

impl TransformError {
    pub fn invalid_input(transform: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidInput {
            transform,
            message: message.into(),
        }
    }
    pub fn skipped(transform: &'static str, message: impl Into<String>) -> Self {
        Self::Skipped {
            transform,
            message: message.into(),
        }
    }
    pub fn internal(transform: &'static str, message: impl Into<String>) -> Self {
        Self::Internal {
            transform,
            message: message.into(),
        }
    }
}

/// Output of a [`ReformatTransform`] — semantically equivalent to the input.
#[derive(Debug, Clone)]
pub struct ReformatOutput {
    pub output: String,
    pub bytes_saved: usize,
}

impl ReformatOutput {
    pub fn from_lengths(input_len: usize, output: String) -> Self {
        Self {
            bytes_saved: input_len.saturating_sub(output.len()),
            output,
        }
    }
}

/// Output of an [`OffloadTransform`] — a subset of the input, with the
/// original in the store under `cache_key` (required, not optional).
#[derive(Debug, Clone)]
pub struct OffloadOutput {
    pub output: String,
    pub bytes_saved: usize,
    /// Key under which the original payload is stored. Trait-required.
    pub cache_key: String,
}

impl OffloadOutput {
    pub fn from_lengths(input_len: usize, output: String, cache_key: String) -> Self {
        Self {
            bytes_saved: input_len.saturating_sub(output.len()),
            output,
            cache_key,
        }
    }
}

/// Per-call context handed to each transform.
#[derive(Debug, Default, Clone)]
pub struct CompressionContext {
    /// User question, for relevance scoring inside offload transforms.
    pub query: String,
    /// Target byte size the orchestrator is aiming for (from the adaptive
    /// sizer; `None` = no budget signal → transforms use their defaults).
    pub target_bytes: Option<usize>,
}

impl CompressionContext {
    pub fn with_query(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            target_bytes: None,
        }
    }
    pub fn with_target(target_bytes: usize) -> Self {
        Self {
            query: String::new(),
            target_bytes: Some(target_bytes),
        }
    }
}

/// Packs the input denser without dropping information. Run first by the
/// orchestrator because no CCR backing is required — surviving bytes
/// round-trip semantically.
pub trait ReformatTransform: Send + Sync {
    /// Stable telemetry name (lowercase snake_case).
    fn name(&self) -> &'static str;
    /// Content types this transform accepts.
    fn applies_to(&self) -> &[ContentType];
    /// Run the transform.
    fn apply(&self, content: &str) -> Result<ReformatOutput, TransformError>;
}

/// Drops bytes from the wire and stashes the original via CCR. Carries a
/// cheap [`estimate_bloat`](Self::estimate_bloat) the orchestrator gates on.
///
/// Contract:
/// 1. `estimate_bloat` returns 0.0–1.0, MUST be cheap (structural only) and
///    safe on any input incl. the empty string (returns 0.0 by convention).
/// 2. `apply` is only called when `estimate_bloat ≥ threshold`. It MUST stash
///    the payload in `store` and the returned `cache_key` MUST resolve there.
pub trait OffloadTransform: Send + Sync {
    fn name(&self) -> &'static str;
    fn applies_to(&self) -> &[ContentType];
    /// Cheap structural bloat estimate for THIS transform's domain. Safe on
    /// empty input.
    fn estimate_bloat(&self, content: &str) -> f32;
    /// Run the offload. Only called when `estimate_bloat(content) ≥ threshold`.
    fn apply(
        &self,
        content: &str,
        ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> Result<OffloadOutput, TransformError>;
    /// Calibrated 0.0–1.0 quality score for telemetry.
    fn confidence(&self) -> f32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::InMemoryCcrStore;

    struct TestReformat;
    impl ReformatTransform for TestReformat {
        fn name(&self) -> &'static str {
            "test_reformat"
        }
        fn applies_to(&self) -> &[ContentType] {
            &[ContentType::PlainText]
        }
        fn apply(&self, content: &str) -> Result<ReformatOutput, TransformError> {
            Ok(ReformatOutput::from_lengths(
                content.len(),
                content.to_string(),
            ))
        }
    }

    struct TestOffload;
    impl OffloadTransform for TestOffload {
        fn name(&self) -> &'static str {
            "test_offload"
        }
        fn applies_to(&self) -> &[ContentType] {
            &[ContentType::PlainText]
        }
        fn estimate_bloat(&self, _content: &str) -> f32 {
            0.9
        }
        fn apply(
            &self,
            content: &str,
            _ctx: &CompressionContext,
            store: &dyn CcrStore,
        ) -> Result<OffloadOutput, TransformError> {
            let key = format!("test_key_{:024x}", content.len());
            store.put(&key, content);
            Ok(OffloadOutput::from_lengths(
                content.len(),
                content.to_string(),
                key,
            ))
        }
        fn confidence(&self) -> f32 {
            0.5
        }
    }

    #[test]
    fn outputs_clamp_negative_savings_to_zero() {
        let r = ReformatOutput::from_lengths(10, "longer than ten bytes".into());
        assert_eq!(r.bytes_saved, 0);
        let o = OffloadOutput::from_lengths(10, "longer than ten".into(), "k".into());
        assert_eq!(o.bytes_saved, 0);
    }

    #[test]
    fn transform_error_messages_round_trip() {
        let e = TransformError::invalid_input("json_minifier", "bad token at line 3");
        let msg = e.to_string();
        assert!(msg.contains("json_minifier") && msg.contains("bad token at line 3"));
    }

    #[test]
    fn compression_context_constructors() {
        let q = CompressionContext::with_query("find errors");
        assert_eq!(q.query, "find errors");
        assert_eq!(q.target_bytes, None);
        let b = CompressionContext::with_target(2048);
        assert!(b.query.is_empty());
        assert_eq!(b.target_bytes, Some(2048));
    }

    #[test]
    fn reformat_trait_smoke() {
        let r = TestReformat.apply("hello").expect("passes through");
        assert_eq!(r.output, "hello");
        assert_eq!(r.bytes_saved, 0);
    }

    #[test]
    fn offload_writes_store_and_returns_required_cache_key() {
        let store = InMemoryCcrStore::new();
        let r = TestOffload
            .apply("hello", &CompressionContext::default(), &store)
            .expect("offload writes");
        assert!(!r.cache_key.is_empty());
        assert_eq!(store.get(&r.cache_key).as_deref(), Some("hello"));
    }

    #[test]
    fn estimate_bloat_safe_on_empty() {
        let _ = TestOffload.estimate_bloat("");
    }
}
