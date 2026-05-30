//! Coding workflow — Hermes-adapted autonomous software engineering
//! scaffold per `PLAN/SPEC_coding_workflow.md`.
//!
//! Maps the Hermes 5-stage workflow onto NEOTH's 3-hemisphere model:
//!
//! ```text
//! Operator prompt
//!     │
//!     ▼
//! Cerebellum (orchestrator)  — decompose + classify + dispatch
//!     │
//!     ├──→ Left (analytic / fast worker)   — well-scoped UI / CRUD / tests
//!     └──→ Right (creative / deep worker)  — architecture / design / review
//!     │
//!     ▼
//! Kanban store (views.db::idx_kanban_*)
//!     │
//!     ▼
//! Activity feed (WAL 0x70..=0x76 frames)
//! ```
//!
//! ## Pick #38 scope (Session 17, 2026-05-19)
//!
//! - Data model (`types.rs`)
//! - Sqlite schema initializer (`store.rs::ensure_schema`)
//! - WAL event-code reservations (in `wal/events.rs` 0x70..=0x76)
//!
//! ## NOT YET LIVE (subsequent picks per SPEC build order)
//!
//! - Pick #2: Store CRUD (sessions/tasks/comments round-trip)
//! - Pick #3: Heuristic complexity classifier
//! - Pick #4: Decomposer (Cerebellum LLM call → list<KanbanTask>)
//! - Pick #5: CLI surface (`neoth code` + `neoth kanban`)
//! - Pick #6: Worker dispatcher
//! - Pick #7-10: Activity feed CLI/GUI + LLM second-opinion + review flow
//!
//! ## References
//!
//! - `PLAN/SPEC_coding_workflow.md` — full contract
//! - `RECON/hermes_coding_workflow.md` — upstream analysis
//! - `cli/hemispheres.rs` — existing hemisphere binding CLI

pub mod analyze;
pub mod brainstorm;
/// QU-05 (Session 28) — `cargo check --message-format=json` diagnostic
/// parser for the validate→fix→escalate loop. Pure-fn half: parse the
/// captured JSON stream into structured diagnostics + format them for
/// re-injection into the next worker attempt's prompt.
pub mod cargo_check;
pub mod cerebellum_provider;
pub mod classifier;
pub mod decomposer;
pub mod dispatcher;
/// QU-01 EarlyStopDetector — pure-fn detectors of degenerate worker
/// behaviour (repetition loops, greeting regressions, patch spirals).
/// Composes with [`retry`] — retry decides strategy rotation, early
/// stop decides whether to bail out of the rotation entirely.
pub mod early_stop;
pub mod feed;
/// Round-3 v0.4 — coding-intent auto-detection for `neoth chat`.
/// Bilingual EN/DE heuristic that flags "build a function" /
/// "fix the bug in" / "schreib mir einen Test" patterns so the
/// chat dispatcher can auto-route to the coding workflow instead
/// of replying with a single chat turn. Operator opt-out via
/// `NEOTH_NO_AUTO_CODE=1` env var.
pub mod intent;
pub mod model_profile;
pub mod plan_writer;
pub mod provider_worker;
pub mod retry;
pub mod review;
pub mod second_opinion;
pub mod store;
/// QU-10b / SP-A1 — pending-task controller loop driving the dispatcher
/// across every session with a Backlog task (`neoth code --run-pending`).
pub mod task_executor;
pub mod tdd_preflight;
pub mod tool_router;
pub mod types;
pub mod validate;
pub mod worker;
pub mod worktree;

// Public re-exports for downstream consumers. Currently unused in main
// because Pick #4+ wires the decomposer/dispatcher/CLI; the module
// surface is pinned now so subsequent picks land without a public-API
// rename. `#[allow(unused_imports)]` is the intended state until Pick #5.
#[allow(unused_imports)]
pub use classifier::{Complexity, classify_heuristic};
#[allow(unused_imports)]
pub use decomposer::{
    CHARS_PER_TOKEN, COST_WARN_USD, DecomposerError, DecomposerLlm, DecomposerResponse,
    DecompositionResult, MAX_INPUT_TOKENS, SessionComplexity, TaskType, build_prompt,
    build_repair_prompt, clamp_task_type, decompose, estimate_input_tokens, parse_response,
    truncate_to_budget, validate_tasks,
};
#[allow(unused_imports)]
pub use feed::{FeedEntry, is_kanban_event, parse_kanban_payload};
#[allow(unused_imports)]
pub use review::{
    ReviewBlocker, auto_promote_if_green, auto_promote_session, check_auto_promotable,
};
#[allow(unused_imports)]
pub use types::{
    Hemisphere, KanbanComment, KanbanSession, KanbanSessionId, KanbanTask, KanbanTaskId,
    SessionStatus, TaskStatus, TestSummary,
};
// Pick #6 Phase 1 (2026-05-20): Worker trait + outcome surface.
// Concrete LeftWorker/RightWorker impls land in Phase 2 once Chorus
// settles the Q1 (patch safety) verdict.
#[allow(unused_imports)]
pub use worker::{Worker, WorkerOutcome};
// Pick #6 Phase 2 (2026-05-20): dispatch_session orchestrator.
// Worker-set binding + budget caps + status transitions live here.
// Concrete LeftWorker/RightWorker impls still pending Chorus verdict
// on Q1 patch safety.
#[allow(unused_imports)]
pub use dispatcher::{DispatchBudget, DispatchOutcome, HemisphereWorkerSet, dispatch_session};
// Pick #6 Phase 3 (2026-05-20): concrete provider-backed worker.
// Hooks Provider trait into Worker trait so the dispatcher can
// actually drive real LLM calls. Q1 patch-safety verdict still
// pending; this commit only stores patches, doesn't apply them.
#[allow(unused_imports)]
pub use provider_worker::{
    ParsedCompletion, ProviderWorker, parse_completion_text, patch_path_for,
};
// Pick #6 Phase 4-pre (2026-05-21): WorkerRetryPolicy ported from
// smallcode's governor — per-task state machine between InProgress
// and Blocked so stuck workers get re-queued with a strategy hint
// before giving up. Per `PLAN/SMALLCODE_INTEGRATION_PLAN_2026-05-21.md`.
#[allow(unused_imports)]
pub use retry::{DEFAULT_MAX_ATTEMPTS, RetryStrategy, WorkerRetryPolicy};
// QU-01 (Session 28): EarlyStopDetector — pure-fn detectors for
// repetition loops, greeting regressions, patch spirals. Composes
// with WorkerRetryPolicy; retry rotates strategy, early-stop bails
// out of the rotation when the worker is degenerate.
#[allow(unused_imports)]
pub use early_stop::{
    DEFAULT_PATCH_SPIRAL_CEILING, GREETING_REGRESSION_MARKERS, PatchSpiralTracker,
    REPETITION_LOOP_MIN_SAMPLES, is_greeting_regression, is_repetition_loop,
};
// QU-05 (Session 28): cargo-check JSON diagnostic parser + retry-hint
// formatter. The dispatcher's Phase-4 test loop feeds the parser the
// captured `cargo check --message-format=json` stdout + re-injects
// `retry_hint_from_cargo_json`'s output into the next worker attempt.
#[allow(unused_imports)]
pub use cargo_check::{
    CargoDiagnostic, MAX_REINJECTED_DIAGNOSTICS, errors_only, format_for_retry, has_errors,
    parse_cargo_check_json, retry_hint_from_cargo_json,
};
// Smallcode port #2 (2026-05-21): per-model capability profiles —
// `ModelProfile` + `ToolFormat` table + fuzzy matcher. Drives
// tool-call formatting (port #3's 2-stage router gates off
// `needs_two_stage_router()`) and operator-readable model awareness
// in `neoth code` debug output. Re-exported pending wire-in by
// `provider_worker::ProviderWorker::execute`.
#[allow(unused_imports)]
pub use model_profile::{ModelProfile, ToolFormat, get_profile, match_profile};
// Pick #9 (2026-05-20): LLM second-opinion classifier for the
// Ambiguous bucket — re-uses the Cerebellum DecomposerLlm trait.
#[allow(unused_imports)]
pub use second_opinion::{
    build_classify_prompt, parse_classify_reply, second_opinion_classify,
    second_opinion_classify_result,
};
