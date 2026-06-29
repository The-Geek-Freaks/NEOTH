/// GOLD-LOOP-01 — multi-round autonomous loop engine.
///
/// Orchestrates N iterate-until-converged outer rounds, each of which calls
/// the existing `cli::chat::run_mcp_dispatch_loop` as its inner engine.
/// The engine evaluates structural stop criteria via
/// `council::stop_verifier::StopConditionVerifier`, optionally fires a
/// `council::self_reflect::refine` pass at L2+ autonomy, emits WAL events
/// (0x7C–0x7F), and writes a `LoopRunRecord` to `~/.neoth/loops/`.
///
/// This module is **not** agentic itself — it purely orchestrates the
/// existing agentic primitives in a converge loop.
pub mod engine;

pub use engine::{run_loop, LoopConfig, LoopRunRecord, LoopRound, LoopState, StopReason};
