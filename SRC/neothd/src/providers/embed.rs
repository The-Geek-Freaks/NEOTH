//! Embedding provider abstraction (Day-14b Phase 1a).
//!
//! Parallel to `Provider` (which is chat-completion only). Three
//! downstreams have stub comments waiting on this surface:
//!   - `skills::router::route_with_embedding` — Stage-2 cosine
//!     re-rank when keyword Stage-1 has ties
//!   - `council::dissent` — cosine dissent score replaces / augments
//!     the existing Jaccard impl
//!   - `daemon::dreaming` / `memory::dimension` — R-02 Phase 3
//!     episodic clustering via cosine grouping
//!
//! Phase 1a (this commit) ships the trait + canonical types + the
//! `EmbedProvider` impl skeleton on `LocalQwenAdapter`. The hidden-
//! state extraction itself is Phase 1b — candle 0.8's
//! `Qwen2::ModelForCausalLM::forward` returns logits, not hidden
//! states, so a thin `providers::qwen2_embed` fork that exposes
//! the pre-`lm_head` activations is required. The trait shape
//! lets consumers wire up against the stable surface today + drop
//! in the real impl without rewriting call sites.
//!
//! **L2 normalisation invariant**: every implementation MUST return
//! unit-length vectors so consumers can use dot-product as cosine
//! distance directly. Length is verified in debug builds via
//! `debug_assert!`; production code trusts the contract.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

/// One embedding request. `model` is the operator-tweakable override
/// (per-call); when None the adapter picks the default checkpoint
/// from its own config block.
#[derive(Debug, Clone)]
pub struct EmbedRequest {
    pub text: String,
    pub model: Option<String>,
}

impl EmbedRequest {
    /// Build a request for the default model. Most callers (skill
    /// router, dissent, dreaming) want this.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            model: None,
        }
    }

    /// Override the model for one call — used by `neoth embed test
    /// --model X` operator probes.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

/// One embedding response. `vector` is L2-normalised (length 1.0
/// within FP tolerance) so cosine = dot product. `model` carries
/// the actual checkpoint that produced the vector (useful for
/// debugging when the operator overrode the per-call model).
#[derive(Debug, Clone)]
pub struct EmbedResponse {
    pub vector: Vec<f32>,
    pub model: String,
    pub latency: Duration,
}

impl EmbedResponse {
    /// Dimensionality of the returned vector. Consumers MUST read
    /// this rather than hard-coding — different models produce
    /// different dims (Qwen2.5-3B = 2048, Qwen2.5-0.5B = 896,
    /// OpenAI text-embedding-3-small = 1536).
    pub fn dim(&self) -> usize {
        self.vector.len()
    }
}

/// Cosine similarity between two L2-normalised vectors. With unit-
/// length inputs this collapses to dot product, which is the cheap
/// path consumers want. Returns 0.0 on dim mismatch so callers
/// can score-then-filter without panicking on a swap-in of a
/// different embedding model mid-run.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// L2-normalise a vector in place. Vectors that are already unit-
/// length (within `1e-6`) are left untouched to avoid drift from
/// repeated normalisation in pipelines. Zero-length input is left
/// as-is (returns `false` — caller's signal to bail).
pub fn l2_normalize(v: &mut [f32]) -> bool {
    let sum_sq: f32 = v.iter().map(|x| x * x).sum();
    if sum_sq <= f32::EPSILON {
        return false;
    }
    let norm = sum_sq.sqrt();
    if (norm - 1.0).abs() < 1e-6 {
        return true;
    }
    for x in v.iter_mut() {
        *x /= norm;
    }
    true
}

/// Every embedding backend implements this. Trait is object-safe
/// so the daemon can hold `Arc<dyn EmbedProvider>` in registries +
/// pass `&dyn EmbedProvider` to pure-function consumers (skill
/// router, dissent, dreaming).
#[async_trait]
pub trait EmbedProvider: Send + Sync {
    /// Short identifier for logs + WAL events: "local_qwen",
    /// "openai_api", "gemini_api", ...
    fn name(&self) -> &'static str;

    /// Vector dimensionality for the adapter's default model. The
    /// skill router uses this for dim-mismatch guards before
    /// computing cosine — embedding a query with one model and
    /// comparing against vectors built with another would silently
    /// return 0.0 via the `cosine()` helper, but pre-checking lets
    /// us surface a clear operator-readable error instead.
    fn default_dim(&self) -> usize;

    /// Produce one embedding. Implementations MUST return an
    /// L2-normalised vector + populate `model` with the actual
    /// checkpoint string.
    async fn embed(&self, req: EmbedRequest) -> Result<EmbedResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_of_identical_vectors_is_one() {
        let v = vec![0.6f32, 0.8, 0.0];
        // Pre-normalised.
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_of_orthogonal_vectors_is_zero() {
        let a = vec![1.0f32, 0.0, 0.0];
        let b = vec![0.0f32, 1.0, 0.0];
        assert!(cosine(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn cosine_of_opposite_vectors_is_negative_one() {
        let a = vec![1.0f32, 0.0];
        let b = vec![-1.0f32, 0.0];
        assert!((cosine(&a, &b) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_on_dim_mismatch_returns_zero() {
        let a = vec![1.0f32; 4];
        let b = vec![1.0f32; 8];
        // Defensive fallback — must not panic.
        assert_eq!(cosine(&a, &b), 0.0);
    }

    #[test]
    fn cosine_on_empty_vectors_returns_zero() {
        let a: Vec<f32> = vec![];
        let b: Vec<f32> = vec![];
        assert_eq!(cosine(&a, &b), 0.0);
    }

    #[test]
    fn l2_normalize_unit_vector_is_noop() {
        let mut v = vec![0.6f32, 0.8, 0.0];
        let ok = l2_normalize(&mut v);
        assert!(ok);
        // Each entry within 1e-6 of the pre-normalised input.
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn l2_normalize_scales_to_unit_length() {
        let mut v = vec![3.0f32, 4.0, 0.0];
        let ok = l2_normalize(&mut v);
        assert!(ok);
        let len_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!((len_sq - 1.0).abs() < 1e-5);
        // 3-4-5 triangle → normalised entries.
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn l2_normalize_rejects_zero_vector() {
        let mut v = vec![0.0f32; 4];
        let ok = l2_normalize(&mut v);
        assert!(!ok, "zero vector cannot be normalised — caller bails");
    }

    #[test]
    fn embed_request_default_model_is_none() {
        let req = EmbedRequest::new("hello");
        assert_eq!(req.text, "hello");
        assert!(req.model.is_none());
    }

    #[test]
    fn embed_request_with_model_override() {
        let req = EmbedRequest::new("hi").with_model("qwen3-q8");
        assert_eq!(req.model.as_deref(), Some("qwen3-q8"));
    }

    #[test]
    fn embed_response_dim_reflects_vector_length() {
        let resp = EmbedResponse {
            vector: vec![0.0; 768],
            model: "test".into(),
            latency: Duration::from_millis(1),
        };
        assert_eq!(resp.dim(), 768);
    }

    // Mock impl to pin trait object-safety + the async wiring.
    struct MockEmbed;

    #[async_trait]
    impl EmbedProvider for MockEmbed {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(&self, req: EmbedRequest) -> Result<EmbedResponse> {
            let mut v = vec![0.0f32; 4];
            // Toy: hash text length into vector[0] so two equal-
            // length strings cluster together.
            v[0] = req.text.len() as f32;
            v[1] = 1.0;
            l2_normalize(&mut v);
            Ok(EmbedResponse {
                vector: v,
                model: req.model.unwrap_or_else(|| "mock-default".to_string()),
                latency: Duration::from_micros(1),
            })
        }
    }

    #[tokio::test]
    async fn trait_object_dispatches_through_dyn_dispatch() {
        let provider: &dyn EmbedProvider = &MockEmbed;
        assert_eq!(provider.name(), "mock");
        assert_eq!(provider.default_dim(), 4);
        let resp = provider
            .embed(EmbedRequest::new("hello world"))
            .await
            .unwrap();
        assert_eq!(resp.dim(), 4);
        let len_sq: f32 = resp.vector.iter().map(|x| x * x).sum();
        assert!(
            (len_sq - 1.0).abs() < 1e-5,
            "mock impl must honour the L2-normalised contract"
        );
    }
}
