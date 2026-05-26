//! Recall-side helpers separate from the `cli::recall` CLI surface.
//!
//! Today: `citation_check` (QM-18). Future: live citation lookup
//! against Crossref/OpenAlex/Semantic Scholar once the outbound HTTP
//! allowlist extends; cross-reference against `idx_groundtruth`.

pub mod citation_check;
pub mod conversational;
