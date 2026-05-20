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

pub mod cerebellum_provider;
pub mod classifier;
pub mod decomposer;
pub mod feed;
pub mod review;
pub mod store;
pub mod types;
pub mod worker;

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
