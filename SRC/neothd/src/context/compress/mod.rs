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
//! Nothing here is wired into a live call path yet — that happens at HR-08
//! (`mcp::dispatch_loop` tool-result blocks, gated on `compression.enabled`).

pub mod content_detector;

pub use content_detector::{detect_content_type, is_json_array_of_dicts, ContentType, DetectionResult};
