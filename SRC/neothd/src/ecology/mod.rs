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
