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
/// F4-01 Phase 3 — tool genealogy. A deterministic, read-only inventory of the
/// tools NEOTH actually exercises (MCP tools via `0xC0`, plugins via
/// `0xC4`/`0xC6`/`0xC2`) + installed skills as zero-count nodes. Surfaced via
/// `neoth ecology genealogy`. TOOL→win co-occurrence edges are precursor-gated
/// on tool-id in the `0x63` winner frame (see module docs); the measurable
/// provider/role/mode winner-chain lives in [`winner_chain`].
pub mod genealogy;
/// F4-01 Phase 1 — Ecology auto-scheduler cron. A 6h tick that detects a
/// low-dissent council regime (winner streak >= `ecology.correlation_min_streak`)
/// and STAGES P-04 self-dev proposals for `neoth self-dev review` (never
/// auto-applies — the DESIGN_CH13 P2 review-gate), emitting
/// `0x4C ECOLOGY_SCHEDULER_FIRED` as the audit trail. Off by default.
pub mod scheduler;
/// F4-01 — council winner-chain: the measured win-distribution (per provider+
/// role, with avg/last score + the selection-mode mix) over the `0x63`
/// winner frames. The part of the blueprint's "winner-chain" that IS grounded
/// in real in-frame fields — distinct from the TOOL→win edges genealogy refuses
/// to fabricate. Surfaced via `neoth ecology winner-chain`.
pub mod winner_chain;
