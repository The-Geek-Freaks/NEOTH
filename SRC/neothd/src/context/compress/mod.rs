//! WS-HR — token-compression pipeline (native Rust port of chopratejas/headroom).
//!
//! Long tool outputs (search results, build logs, diffs, JSON dumps, fetched
//! web pages) dominate the prompt budget of every LLM call NEOTH makes. This
//! module shrinks them *before* they reach a provider, while keeping the
//! answer safe: the guiding principle, inherited from headroom, is
//! **information preservation > aggressive compression**.
//!
//! Build order (see `PLAN/ROAD_TO_1_0_GOLD.md` §WS-HR):
//!
//! - **HR-01** [`content_detector`] — classify a block so the router can pick a
//!   compressor. Heuristic regex only; the `magika` ML detector is OUT.
//! - **HR-03** `ccr` — Content-Caching-and-Retrieval: stash the original under
//!   `md5[:24]` and emit a retrieval marker, so every lossy transform stays
//!   answer-safe (the dropped text is one `neoth ctx retrieve <key>` away).
//! - **HR-02** `pipeline` — orchestrator + adaptive sizing + the live-zone
//!   guard (the most-recent turns are never touched). Gated on
//!   `freedom.yaml::compression{enabled:false}`; disabled = byte-identical
//!   passthrough.
//! - **HR-04..07** per-type compressors (log, diff, smart-crusher, search).
//!
//! Wired live at HR-08 (`mcp::dispatch_loop` tool-result blocks, gated on
//! `compression.enabled`).
//!
//! ## Attribution & upstream resync (GOLD-HR-11)
//!
//! These transforms are a native Rust port of headroom's `headroom-core`
//! (chopratejas/headroom, Apache-2.0). The full attribution, the per-file
//! provenance table (headroom path → NEOTH file), and the list of deliberate
//! modifications (magika OUT, SHA-256 CCR key, sequential pipeline, lean
//! crushers) live in the repo-root `THIRD_PARTY_LICENSES`. When resyncing from
//! a newer upstream, walk that table file-by-file; the per-module doc headers
//! name their specific upstream source.

pub mod ccr;
pub mod ccr_file;
pub mod content_detector;
pub mod diff_compressor;
pub mod log_compressor;
pub mod log_template;
pub mod pipeline;
pub mod search_compressor;
pub mod smart_crusher;
pub mod tag_protector;
pub mod transform;

pub use ccr::{
    compute_key, extract_keys, marker_for, retrieve, stash, CcrStore, InMemoryCcrStore,
    DEFAULT_CAPACITY, DEFAULT_TTL,
};
pub use ccr_file::{default_ccr_dir, read_savings, record_savings, FileCcrStore, Savings};
pub use content_detector::{detect_content_type, is_json_array_of_dicts, ContentType, DetectionResult};
pub use pipeline::{
    default_pipeline, in_live_zone, target_bytes_for_budget, CompressionPipeline,
    CompressionPipelineBuilder, CompressionRuntime, CompressionSkip, Gate, PipelineResult,
    Thresholds, BYTES_PER_TOKEN_ESTIMATE,
};
pub use transform::{
    CompressionContext, OffloadOutput, OffloadTransform, ReformatOutput, ReformatTransform,
    TransformError,
};
pub use diff_compressor::{DiffCompressor, DiffCompressorConfig};
pub use log_compressor::{line_importance, LogOffload, LogOffloadConfig};
pub use log_template::{LogTemplate, LogTemplateConfig};
pub use search_compressor::{SearchOffload, SearchOffloadConfig};
pub use smart_crusher::{JsonMinifier, SmartCrusher, SmartCrusherConfig};
pub use tag_protector::{has_protected_regions, is_fence_delimiter, protected_line_mask};
