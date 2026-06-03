//! CH-13 — Ecology layer (self-improvement / self-adaptation loop).
//!
//! Per `PLAN/DESIGN_CH13_ecology_schicht_2026-05-23.md`, this layer sits above
//! council → profile → memory → WAL and decides WHEN NEOTH adapts itself
//! (vs P-04 which decides WHAT to propose). The full layer is a multi-slice
//! workstream; this module currently ships **F4-01's read-only fitness
//! scanner** — [`correlation_detector`] — with the auto-scheduler, genealogy
//! graph, and the `0xEC/0xED/0xEE` ecology WAL events landing as their own
//! slices.
//!
//! Design pin: the Ecology layer is **deterministic + LLM-free** — every
//! signal is a pure function over WAL data.

pub mod correlation_detector;
/// F4-01 Phase 1 — Ecology auto-scheduler cron. A 6h tick that detects a
/// low-dissent council regime (winner streak >= `ecology.correlation_min_streak`)
/// and STAGES P-04 self-dev proposals for `neoth self-dev review` (never
/// auto-applies — the DESIGN_CH13 P2 review-gate), emitting
/// `0x4C ECOLOGY_SCHEDULER_FIRED` as the audit trail. Off by default.
pub mod scheduler;
