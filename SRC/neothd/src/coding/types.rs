//! Core data types for the coding workflow per
//! `PLAN/SPEC_coding_workflow.md` §Data model. Pure types — no IO, no
//! sqlite, no async. Mirrors the Hermes kanban_db schema field-for-field
//! so the on-disk wire form is operator-compatible with the upstream
//! Hermes Kanban tool when both run side-by-side.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Strongly-typed session identifier — wraps a sqlite ROWID. Newtype
/// per `rules/rust/patterns.md` so a `KanbanSessionId` can never
/// silently swap with a `KanbanTaskId` at call sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KanbanSessionId(pub i64);

impl KanbanSessionId {
    pub const fn raw(self) -> i64 {
        self.0
    }
}

/// Strongly-typed task identifier — wraps a sqlite ROWID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KanbanTaskId(pub i64);

impl KanbanTaskId {
    pub const fn raw(self) -> i64 {
        self.0
    }
}

/// Task lifecycle status. Five-state chain mirrors the Hermes
/// `BOARD_COLUMNS` contract in `kanban_bridge.py:25`:
/// `["triage", "todo", "ready", "running", "blocked", "done"]`. NEOTH
/// collapses `triage`/`ready` into `Backlog`/`Todo` (NEOTH triages
/// during decomposition before the task surfaces), keeps `Blocked` as
/// a side channel, and adds `Review` between `InProgress` and `Done`
/// because the SPEC's worker dispatch always produces a patch that
/// needs a Right-hemisphere review pass before merge.
///
/// Wire form (snake_case) is what gets stored in `idx_kanban_task.status`
/// and emitted in WAL 0x73 KANBAN_STATUS_CHANGED frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskStatus {
    Backlog,
    Todo,
    InProgress,
    Review,
    Done,
    Blocked,
    Archived,
}

impl TaskStatus {
    /// Stable on-disk wire form. WAL payloads + sqlite rows + CLI
    /// `--status` flags MUST agree on this string.
    pub const fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Backlog => "backlog",
            TaskStatus::Todo => "todo",
            TaskStatus::InProgress => "in_progress",
            TaskStatus::Review => "review",
            TaskStatus::Done => "done",
            TaskStatus::Blocked => "blocked",
            TaskStatus::Archived => "archived",
        }
    }

    /// Parse the wire form back. Returns `None` for unknown strings —
    /// callers decide whether to bail or default. Forward-compatible:
    /// future status additions surface as `None` in older builds, not
    /// a panic.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "backlog" => Some(Self::Backlog),
            "todo" => Some(Self::Todo),
            "in_progress" => Some(Self::InProgress),
            "review" => Some(Self::Review),
            "done" => Some(Self::Done),
            "blocked" => Some(Self::Blocked),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }

    /// Returns true when the task has reached a state that no longer
    /// consumes worker capacity. The dispatcher uses this to decide
    /// whether to advance the next BACKLOG task.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Archived)
    }
}

/// Worker assignment slot. Maps directly to the [`InferenceTopology`]
/// hemisphere ladder (`config::inference::HemisphereRole`) but stays
/// in this module because the coding workflow only needs the role
/// label — not the full per-role provider binding.
///
/// [`InferenceTopology`]: crate::config::inference
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Hemisphere {
    /// Analytic / fast worker — well-scoped UI scaffolds, CRUD, test
    /// stubs, single-file edits. Maps to the Left hemisphere's bound
    /// provider (typically a local fast model: Ollama, local_qwen).
    Left,
    /// Creative / deep worker — architecture, design decisions, code
    /// review, ambiguous specs. Maps to the Right hemisphere (typically
    /// a remote heavy model: claude-opus, gpt-4o, codex).
    Right,
    /// Orchestrator role. Tasks assigned here are meta — decomposition,
    /// classification, final review. Rare assignment in steady state.
    Cerebellum,
    /// Default for freshly-decomposed tasks before the classifier runs.
    Unassigned,
}

impl Hemisphere {
    pub const fn as_str(self) -> &'static str {
        match self {
            Hemisphere::Left => "left",
            Hemisphere::Right => "right",
            Hemisphere::Cerebellum => "cerebellum",
            Hemisphere::Unassigned => "unassigned",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "left" => Some(Self::Left),
            "right" => Some(Self::Right),
            "cerebellum" => Some(Self::Cerebellum),
            "unassigned" => Some(Self::Unassigned),
            _ => None,
        }
    }
}

/// Final test outcome a worker reports back as part of its task
/// completion payload. Stored in `idx_kanban_task.test_summary` as
/// JSON; the operator-facing summary panel reads it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestSummary {
    pub added: u32,
    pub total: u32,
    pub passing: u32,
    pub failing: u32,
    pub skipped: u32,
}

impl TestSummary {
    pub const ZERO: Self = Self {
        added: 0,
        total: 0,
        passing: 0,
        failing: 0,
        skipped: 0,
    };

    /// All declared tests pass + at least one ran. Used by the
    /// dispatcher to decide whether REVIEW can auto-promote to DONE.
    pub const fn all_green(self) -> bool {
        self.total > 0 && self.failing == 0 && self.passing == self.total - self.skipped
    }
}

/// Session-level lifecycle status. The Cerebellum orchestrator manages
/// transitions: a session opens in `Planning` while the decomposer runs,
/// moves to `Running` once at least one task is assigned, sits in
/// `Review` while REVIEW-column tasks await final pass, lands in `Done`
/// when every task is terminal AND a summary is written, or `Abandoned`
/// when the operator explicitly archives mid-flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionStatus {
    Planning,
    Running,
    Review,
    Done,
    Abandoned,
}

impl SessionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Planning => "planning",
            SessionStatus::Running => "running",
            SessionStatus::Review => "review",
            SessionStatus::Done => "done",
            SessionStatus::Abandoned => "abandoned",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "planning" => Some(Self::Planning),
            "running" => Some(Self::Running),
            "review" => Some(Self::Review),
            "done" => Some(Self::Done),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Abandoned)
    }
}

/// One kanban session row. Stored in `idx_kanban_session`. One session
/// = one `neoth code "..."` invocation = N tasks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanSession {
    pub session_id: KanbanSessionId,
    pub created_ns: u64,
    pub prompt: String,
    pub prompt_hash: String,
    pub source_channel: String,
    pub operator_id: Option<String>,
    pub status: SessionStatus,
    pub artifact_path: Option<std::path::PathBuf>,
    pub summary: Option<String>,
}

/// One comment row. Stored in `idx_kanban_comment`. Both inter-worker
/// comments (Left leaves a note on Right's task) and operator-side
/// remarks land here; the `author` discriminates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanComment {
    pub comment_id: i64,
    pub task_id: KanbanTaskId,
    pub author: String,
    pub body: String,
    pub created_ns: u64,
}

/// One kanban task row. Stored in `idx_kanban_task`. Construction goes
/// through [`store::insert_task`] which assigns the rowid — callers
/// receive the populated struct back.
///
/// [`store::insert_task`]: crate::coding::store
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanTask {
    pub task_id: KanbanTaskId,
    pub session_id: KanbanSessionId,
    pub status: TaskStatus,
    pub title: String,
    pub description: Option<String>,
    pub task_type: String,
    pub hemisphere: Hemisphere,
    pub worker: Option<String>,
    pub parent_task_id: Option<KanbanTaskId>,
    pub created_ns: u64,
    pub started_ns: Option<u64>,
    pub eta_ns: Option<u64>,
    pub completed_ns: Option<u64>,
    pub patch_path: Option<PathBuf>,
    pub test_summary: Option<TestSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_status_wire_form_is_snake_case_and_round_trips() {
        // Operators grep `neoth wal show --type 0x73 --json | jq .new_status`
        // + the CLI's `--status` flag accepts the same wire form. Pin
        // the exact bytes so a Rename surfaces here, not in operator
        // dashboards.
        for s in [
            TaskStatus::Backlog,
            TaskStatus::Todo,
            TaskStatus::InProgress,
            TaskStatus::Review,
            TaskStatus::Done,
            TaskStatus::Blocked,
            TaskStatus::Archived,
        ] {
            let wire = s.as_str();
            assert_eq!(TaskStatus::from_wire(wire), Some(s), "round-trip {wire}");
            assert!(
                wire.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "status wire form must be snake_case: {wire:?}"
            );
        }
    }

    #[test]
    fn task_status_from_wire_rejects_unknown() {
        // Forward-compat: an older build seeing a v0.2 status MUST
        // return None, not panic. The dispatcher's match arms then
        // decide whether to bail or default to Blocked.
        assert!(TaskStatus::from_wire("triage").is_none());
        assert!(TaskStatus::from_wire("").is_none());
        assert!(TaskStatus::from_wire("DONE").is_none(), "case-sensitive");
    }

    #[test]
    fn task_status_terminal_set_matches_spec() {
        // Done + Archived terminate the lifecycle — the dispatcher
        // uses `is_terminal` to advance the next BACKLOG task.
        assert!(TaskStatus::Done.is_terminal());
        assert!(TaskStatus::Archived.is_terminal());
        assert!(!TaskStatus::Backlog.is_terminal());
        assert!(!TaskStatus::Todo.is_terminal());
        assert!(!TaskStatus::InProgress.is_terminal());
        assert!(!TaskStatus::Review.is_terminal());
        assert!(!TaskStatus::Blocked.is_terminal());
    }

    #[test]
    fn hemisphere_wire_form_is_snake_case_and_round_trips() {
        for h in [
            Hemisphere::Left,
            Hemisphere::Right,
            Hemisphere::Cerebellum,
            Hemisphere::Unassigned,
        ] {
            let wire = h.as_str();
            assert_eq!(Hemisphere::from_wire(wire), Some(h), "round-trip {wire}");
        }
        assert!(Hemisphere::from_wire("middle").is_none());
        assert!(Hemisphere::from_wire("LEFT").is_none());
    }

    #[test]
    fn test_summary_all_green_requires_at_least_one_test() {
        // A patch that ships ZERO tests does NOT auto-promote to DONE.
        // The dispatcher requires evidence of testing before bypassing
        // the operator-review gate.
        assert!(
            !TestSummary::ZERO.all_green(),
            "zero-test summary must NOT count as all-green — \
             blocks worker patches that skip tests entirely"
        );
        assert!(
            TestSummary {
                added: 5,
                total: 5,
                passing: 5,
                failing: 0,
                skipped: 0,
            }
            .all_green()
        );
        assert!(
            !TestSummary {
                added: 5,
                total: 5,
                passing: 4,
                failing: 1,
                skipped: 0,
            }
            .all_green()
        );
        // Skipped tests are tolerated as long as the rest pass.
        assert!(
            TestSummary {
                added: 5,
                total: 5,
                passing: 4,
                failing: 0,
                skipped: 1,
            }
            .all_green()
        );
    }

    #[test]
    fn session_status_wire_form_round_trips() {
        for s in [
            SessionStatus::Planning,
            SessionStatus::Running,
            SessionStatus::Review,
            SessionStatus::Done,
            SessionStatus::Abandoned,
        ] {
            let wire = s.as_str();
            assert_eq!(SessionStatus::from_wire(wire), Some(s), "round-trip {wire}");
            assert!(
                wire.chars().all(|c| c.is_ascii_lowercase()),
                "session status wire form must be lowercase: {wire:?}"
            );
        }
        assert!(SessionStatus::from_wire("unknown").is_none());
        assert!(SessionStatus::from_wire("DONE").is_none());
    }

    #[test]
    fn session_status_terminal_set_matches_spec() {
        assert!(SessionStatus::Done.is_terminal());
        assert!(SessionStatus::Abandoned.is_terminal());
        assert!(!SessionStatus::Planning.is_terminal());
        assert!(!SessionStatus::Running.is_terminal());
        assert!(!SessionStatus::Review.is_terminal());
    }

    #[test]
    fn newtype_ids_are_not_swappable() {
        // Newtype pattern is the whole point — pin that the API
        // distinguishes them at the type system level. (Compile-fail
        // test would be cleaner but `trybuild` isn't in deps; this
        // smoke-test enforces the field accessor at least.)
        let s = KanbanSessionId(42);
        let t = KanbanTaskId(42);
        assert_eq!(s.raw(), 42);
        assert_eq!(t.raw(), 42);
        // `s.raw() == t.raw()` compiles, but the types themselves
        // do not interconvert without an explicit `.raw()` round-trip.
    }
}
