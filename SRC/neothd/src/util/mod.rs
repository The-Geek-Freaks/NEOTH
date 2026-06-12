//! Small cross-cutting utilities shared across NEOTH subsystems.
//!
//! Helpers here are deliberately dependency-light and domain-agnostic — they
//! encode one mechanical concern (crash-safe writes, encoding, …) that several
//! modules would otherwise hand-roll inconsistently. Extracted under WS-E
//! (architecture debt) to kill copy-pasted variants.

pub mod atomic_write;
pub mod url_encode;
