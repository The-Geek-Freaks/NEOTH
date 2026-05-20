//! Architecture Decision Records (ADRs) — Phase 31 R-21.
//!
//! When a provider response contains a decision marker (`DECISION:` /
//! `Beschluss:` / `ADR:`), NEOTH extracts it into a numbered MD file under
//! `~/.neoth/adr/NNNN-<slug>.md`. Operators get a Michael-Nygard-style ADR
//! log without having to write it by hand.
//!
//! ## Layout
//!
//! ```text
//! ~/.neoth/adr/
//!   0001-use-rusqlite-bundled.md
//!   0002-wal-segment-rotation-at-16-mib.md
//!   ...
//! ```
//!
//! Numbering is monotonic and never reused — even after deletion the next
//! file picks `max(existing) + 1`. This keeps cross-references in
//! commit messages and operator notes stable.

pub mod extractor;
pub mod store;

pub use extractor::extract_decisions;
pub use store::{default_adr_dir, list_adrs, write_adr};
