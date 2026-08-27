//! Activity feed — pure derived view over WAL 0x70..=0x76 frames.
//!
//! Pick #7 per `PLAN/SPEC_coding_workflow.md` build order. Pure
//! functions only — no IO, no daemon. Pick #5 will wire `neoth kanban
//! watch` to walk a segment + tail new frames + call into here for
//! formatting.
//!
//! ## Output shape (matches the Twitter image)
//!
//! ```text
//! 23:55  left        Patch generated for toggle component
//! 23:56  left        Tests added (5 new)
//! 23:57  right       Code review started
//! 23:58  cerebellum  All checks passing
//! ```
//!
//! The columns are: HH:MM (local time) | actor (left/right/cerebellum
//! /operator/system) | one-line message. The actor comes from the
//! kanban payload's `hemisphere` or `author` field; the message is
//! derived from the event type + payload context.

use serde::{Deserialize, Serialize};

use crate::wal::events::{
    EVENT_TYPE_KANBAN_SESSION_CLOSED, EVENT_TYPE_KANBAN_SESSION_OPENED,
    EVENT_TYPE_KANBAN_STATUS_CHANGED, EVENT_TYPE_KANBAN_TASK_ASSIGNED,
    EVENT_TYPE_KANBAN_TASK_COMMENT, EVENT_TYPE_KANBAN_TASK_COMPLETED,
    EVENT_TYPE_KANBAN_TASK_CREATED, EVENT_TYPE_KANBAN_TASK_DEP_ADDED,
    EVENT_TYPE_KANBAN_TASK_DEP_REMOVED, EVENT_TYPE_KANBAN_TASK_PROGRESS,
};

/// One formatted line in the activity feed. Pick #5's `neoth kanban
/// watch` collects these from a segment walk + prints them in time
/// order. The struct stays public so future GUI bindings (Pick #8)
/// can read the same shape without re-parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FeedEntry {
    /// Nanoseconds since unix epoch, taken from the WAL header's HLC
    /// physical component. The formatter converts to HH:MM:SS at
    /// render time so callers can re-render in any timezone.
    pub ts_ns: u64,
    /// Stable WAL event-type byte (0x70..=0x76). Operators reading
    /// the raw feed can correlate with `neoth events --grep kanban`.
    /// Babel observer lines (GOLD-DELTA-11) use `0x00` = no WAL
    /// correlate — that subsystem is SQLite-only (byte space exhausted).
    pub event_type: u8,
    /// Who is doing the thing. `left` / `right` / `cerebellum` for
    /// worker actions; `operator` for human input; `system` for
    /// session-lifecycle frames (session opened/closed without a
    /// specific actor).
    pub actor: String,
    /// One-line operator-readable description. Already includes
    /// task title or test count where the payload carries it; the
    /// formatter does NOT re-derive these on render.
    pub message: String,
}

impl FeedEntry {
    /// Render as a single feed line: `HH:MM:SS  actor       message`.
    /// Actor is left-padded to 11 chars (matches the Twitter image's
    /// column width) so a sequence of entries lines up cleanly.
    pub fn format(&self) -> String {
        format!(
            "{}  {:<11} {}",
            format_hms_utc(self.ts_ns),
            self.actor,
            self.message,
        )
    }
}

/// GOLD-ADAPT-TRAIL-02: query the most-recent row from
/// `idx_kanban_task_event` and parse it as a [`FeedEntry`].
///
/// Called from the kanban-SSE relay task in `cli/serve.rs` after the
/// views.db change-bus fires. Returns `None` when the table is empty
/// or the most-recent row cannot be parsed (corrupt / unknown event
/// type) — the relay task discards silently in that case and waits for
/// the next change signal.
pub fn latest_feed_entry_from_db(conn: &rusqlite::Connection) -> Option<FeedEntry> {
    conn.query_row(
        "SELECT event_type, created_ns, payload \
         FROM idx_kanban_task_event \
         ORDER BY event_id DESC LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)? as u8,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, String>(2)?,
            ))
        },
    )
    .ok()
    .and_then(|(et, ts, payload)| parse_kanban_payload(et, ts, payload.as_bytes()))
}

/// Returns `true` when the event-type byte belongs to the coding
/// band (0x70..=0x7F). Pick #5's tail loop uses this to skip every
/// frame that isn't kanban-related without parsing the payload.
pub const fn is_kanban_event(event_type: u8) -> bool {
    matches!(event_type, 0x70..=0x7F)
}

/// Parse the JSON payload of a kanban WAL frame into a `FeedEntry`.
/// Returns `None` when the payload doesn't deserialise to a known
/// shape — the caller surfaces the bad-frame count via `wal stats`
/// rather than the feed view (a corrupt frame is an operator-level
/// concern, not something the operator wants in their kanban tail).
pub fn parse_kanban_payload(event_type: u8, ts_ns: u64, payload_bytes: &[u8]) -> Option<FeedEntry> {
    match event_type {
        EVENT_TYPE_KANBAN_SESSION_OPENED => parse_session_opened(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_CREATED => parse_task_created(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_ASSIGNED => parse_task_assigned(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_STATUS_CHANGED => parse_status_changed(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_COMMENT => parse_task_comment(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_COMPLETED => parse_task_completed(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_SESSION_CLOSED => parse_session_closed(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_PROGRESS => parse_task_progress(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_DEP_ADDED => parse_dep_added(ts_ns, payload_bytes),
        EVENT_TYPE_KANBAN_TASK_DEP_REMOVED => parse_dep_removed(ts_ns, payload_bytes),
        _ => None,
    }
}

// ── Payload schemas ────────────────────────────────────────────────────────
//
// One Deserialize struct per event type. Pick #4 (decomposer) +
// Pick #6 (dispatcher) emit these — keep these in sync with the
// JSON shapes they produce. `#[serde(default)]` on optional fields
// so a future schema addition stays backwards-readable.

#[derive(Deserialize)]
struct SessionOpenedPayload {
    #[allow(dead_code)]
    session_id: i64,
    // Mirrors the emitted JSON shape (schema doc, same as session_id);
    // no reader yet.
    #[allow(dead_code)]
    #[serde(default)]
    prompt_hash: String,
    #[serde(default)]
    source_channel: String,
    #[serde(default)]
    operator_id: Option<String>,
}

#[derive(Deserialize)]
struct TaskCreatedPayload {
    #[allow(dead_code)]
    session_id: i64,
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    task_type: String,
    #[serde(default)]
    title: String,
}

#[derive(Deserialize)]
struct TaskAssignedPayload {
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    hemisphere: String,
    #[serde(default)]
    worker: Option<String>,
    #[serde(default)]
    eta_ns: Option<u64>,
}

#[derive(Deserialize)]
struct StatusChangedPayload {
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    old_status: String,
    #[serde(default)]
    new_status: String,
}

#[derive(Deserialize)]
struct TaskCommentPayload {
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    author: String,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct TaskCompletedPayload {
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    tests_added: u32,
    #[serde(default)]
    tests_passing: u32,
    #[serde(default)]
    tests_failing: u32,
}

#[derive(Deserialize)]
struct SessionClosedPayload {
    #[allow(dead_code)]
    session_id: i64,
    #[serde(default)]
    status: String,
    #[serde(default)]
    tasks_done: u32,
    #[serde(default)]
    tasks_archived: u32,
}

/// SD-02 — payload of `0x77 KANBAN_TASK_PROGRESS`, emitted by the
/// dispatcher on each task lifecycle transition (dispatched=0% /
/// review_ready=100%). Only the feed-rendered fields are decoded.
#[derive(Deserialize)]
struct TaskProgressPayload {
    #[allow(dead_code)]
    task_id: i64,
    #[serde(default)]
    hemisphere: String,
    #[serde(default)]
    progress_pct: u8,
    #[serde(default)]
    message: String,
}

// ── Parsers ────────────────────────────────────────────────────────────────

fn parse_session_opened(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: SessionOpenedPayload = serde_json::from_slice(payload).ok()?;
    let via = if p.source_channel.is_empty() {
        "cli".to_string()
    } else {
        p.source_channel
    };
    let by = match p.operator_id {
        Some(id) if !id.is_empty() => format!(" by {id}"),
        _ => String::new(),
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_SESSION_OPENED,
        actor: "system".to_string(),
        message: format!("Session opened via {via}{by}"),
    })
}

fn parse_task_created(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: TaskCreatedPayload = serde_json::from_slice(payload).ok()?;
    let kind = if p.task_type.is_empty() {
        String::new()
    } else {
        format!(" [{}]", p.task_type)
    };
    let title = if p.title.is_empty() {
        "(untitled)".to_string()
    } else {
        p.title
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_CREATED,
        actor: "cerebellum".to_string(),
        message: format!("Task created: {title}{kind}"),
    })
}

fn parse_task_assigned(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: TaskAssignedPayload = serde_json::from_slice(payload).ok()?;
    let actor = if p.hemisphere.is_empty() {
        "cerebellum".to_string()
    } else {
        p.hemisphere
    };
    let worker = match p.worker.as_deref() {
        Some(w) if !w.is_empty() => format!(" → worker `{w}`"),
        _ => String::new(),
    };
    let eta = match p.eta_ns {
        Some(ns) if ns > 0 => format!(" (eta {})", format_eta(ns)),
        _ => String::new(),
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_ASSIGNED,
        actor,
        message: format!("Task assigned{worker}{eta}"),
    })
}

fn parse_status_changed(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: StatusChangedPayload = serde_json::from_slice(payload).ok()?;
    if p.new_status.is_empty() {
        return None;
    }
    let from = if p.old_status.is_empty() {
        "?".to_string()
    } else {
        p.old_status
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_STATUS_CHANGED,
        actor: "system".to_string(),
        message: format!("Status: {from} → {}", p.new_status),
    })
}

/// GOLD-TASK-03 — render a fixed-width 8-cell Unicode progress bar for a
/// 0–100 percent, `[████░░░░]` style. Used in the `kanban watch` activity
/// feed so a task's lifecycle heartbeat is glanceable as a bar, not just a
/// number. Cells are filled by NEAREST rounding (each cell = 12.5%), so
/// 0% → all empty, 100% → all full, 50% → 4 filled. `pct` is clamped to
/// 100 (a malformed >100 frame can't overflow the cell count).
pub(crate) fn progress_bar(pct: u8) -> String {
    const CELLS: usize = 8;
    let p = (pct as usize).min(100);
    let filled = ((p * CELLS + 50) / 100).min(CELLS);
    let empty = CELLS - filled;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

/// GOLD-TASK-03 — a channel-agnostic, single-line summary of a FINISHED
/// coding session, for the proactive "here's the result of the task you
/// gave me" notification. Uses ONLY [`DispatchOutcome`] counts + the
/// numeric session id — NO task titles / LLM output — so the body carries
/// zero injection / PII risk and needs no per-channel escaping (the
/// proactive channel adapters apply their own light formatting on top of
/// this `body`). The bar reflects the completed/attempted ratio; the lead
/// icon is ✅ all-done / ⚠️ any-blocked / 🔧 otherwise.
pub(crate) fn render_session_summary(
    outcome: &crate::coding::dispatcher::DispatchOutcome,
    session_id: i64,
) -> String {
    let total = outcome.tasks_attempted;
    let done = outcome.tasks_completed;
    let pct = (done * 100).checked_div(total).unwrap_or(0).min(100) as u8;
    let icon = if total == 0 {
        "🔧"
    } else if outcome.tasks_blocked == 0 && done == total {
        "✅"
    } else if outcome.tasks_blocked > 0 {
        "⚠️"
    } else {
        "🔧"
    };
    let mut s = format!(
        "{icon} Coding session #{session_id}: {} {done}/{total} tasks done",
        progress_bar(pct)
    );
    if outcome.tasks_blocked > 0 {
        s.push_str(&format!(" — {} blocked", outcome.tasks_blocked));
    }
    if outcome.tasks_unassigned > 0 {
        s.push_str(&format!(", {} unassigned", outcome.tasks_unassigned));
    }
    if outcome.budget_exhausted {
        s.push_str(" (budget exhausted)");
    }
    s
}

/// GOLD-TASK-03 — priority tier for the coding session-summary proactive
/// item. BELOW the reflection-nudge tier (50) so a burst of coding sessions
/// can't starve reflections out of the daily proactive budget; above
/// background telemetry (10). Dedup (one item per session id) caps the
/// volume regardless of priority.
pub(crate) const SESSION_SUMMARY_PRIORITY: i32 = 30;

/// GOLD-TASK-03 — build the proactive-queue item for a finished coding
/// session. Pure (no I/O) so the item shape — the session-scoped
/// `dedup_key` (one summary per session, so it can never flood the daily
/// budget), the low priority, the counts-only body — is unit-testable. The
/// `channel` is left empty so the drain routes to the operator's default
/// proactive channel; `scheduled_for_unix = 0` drains it on the next tick.
pub(crate) fn build_session_summary_item(
    outcome: &crate::coding::dispatcher::DispatchOutcome,
    session_id: i64,
) -> crate::proactive::ProactiveItem {
    let failed = outcome.tasks_blocked > 0;
    crate::proactive::ProactiveItem {
        // F37 — a partial-failure coding summary is the genuine URGENT_PRIORITY
        // producer: it early-surfaces (the `priority >= URGENT_PRIORITY` bypass in
        // proactive::ProactiveQueue::drain) so a blocked session reaches the
        // operator on the next tick instead of waiting for its scheduled time. A
        // clean summary stays low-priority background telemetry.
        priority: if failed {
            crate::proactive::URGENT_PRIORITY
        } else {
            SESSION_SUMMARY_PRIORITY
        },
        dedup_key: format!("coding:session-summary:{session_id}"),
        channel: String::new(),
        source: "coding_session".to_string(),
        body: render_session_summary(outcome, session_id),
        scheduled_for_unix: 0,
        // GOLD-FEAT-13 — a session that ended with blocked tasks is a
        // partial failure → routing prefers the operator's failure_channel.
        is_failure: failed,
        expires_unix: 0, // a coding-session summary stays relevant
    }
}

/// SD-02 — render the dispatcher's lifecycle heartbeat (`0x77`) into a
/// feed line, so `neoth kanban watch` shows "dispatched" / "review-ready"
/// progress. The actor is the hemisphere that ran the task (or `system`
/// when unset); the message carries a Unicode progress bar + the percent +
/// the dispatcher's note (GOLD-TASK-03 prettified the bar prefix).
fn parse_task_progress(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: TaskProgressPayload = serde_json::from_slice(payload).ok()?;
    let actor = if p.hemisphere.is_empty() {
        "system".to_string()
    } else {
        p.hemisphere
    };
    let bar = progress_bar(p.progress_pct);
    let message = if p.message.is_empty() {
        format!("{bar} {}% complete", p.progress_pct)
    } else {
        format!("{bar} {}% — {}", p.progress_pct, p.message)
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_PROGRESS,
        actor,
        message,
    })
}

fn parse_task_comment(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: TaskCommentPayload = serde_json::from_slice(payload).ok()?;
    let actor = if p.author.is_empty() {
        "operator".to_string()
    } else {
        p.author
    };
    let body = truncate_message(&p.body, 80);
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_COMMENT,
        actor,
        message: format!("\"{body}\""),
    })
}

fn parse_task_completed(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: TaskCompletedPayload = serde_json::from_slice(payload).ok()?;
    let test_summary = if p.tests_added + p.tests_failing == 0 {
        "no tests".to_string()
    } else if p.tests_failing == 0 {
        format!("{} tests added, all passing", p.tests_added)
    } else {
        format!(
            "{} added, {} failing of {} total",
            p.tests_added,
            p.tests_failing,
            p.tests_passing + p.tests_failing,
        )
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_COMPLETED,
        actor: "system".to_string(),
        message: format!("Task completed — {test_summary}"),
    })
}

fn parse_session_closed(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: SessionClosedPayload = serde_json::from_slice(payload).ok()?;
    let status = if p.status.is_empty() {
        "done".to_string()
    } else {
        p.status
    };
    let counts = if p.tasks_done + p.tasks_archived == 0 {
        String::new()
    } else {
        format!(" ({} done, {} archived)", p.tasks_done, p.tasks_archived)
    };
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_SESSION_CLOSED,
        actor: "cerebellum".to_string(),
        message: format!("Session closed: {status}{counts}"),
    })
}

// ── Dep-edge parsers (GOLD-ADAPT-HERMES-08) ───────────────────────────────

#[derive(Deserialize)]
struct DepEdgePayload {
    task_id: i64,
    depends_on_task_id: i64,
}

fn parse_dep_added(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: DepEdgePayload = serde_json::from_slice(payload).ok()?;
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_DEP_ADDED,
        actor: "system".to_string(),
        message: format!(
            "dep added: task {} → depends on {}",
            p.task_id, p.depends_on_task_id
        ),
    })
}

fn parse_dep_removed(ts_ns: u64, payload: &[u8]) -> Option<FeedEntry> {
    let p: DepEdgePayload = serde_json::from_slice(payload).ok()?;
    Some(FeedEntry {
        ts_ns,
        event_type: EVENT_TYPE_KANBAN_TASK_DEP_REMOVED,
        actor: "system".to_string(),
        message: format!(
            "dep removed: task {} no longer depends on {}",
            p.task_id, p.depends_on_task_id
        ),
    })
}

// ── Tiny helpers ───────────────────────────────────────────────────────────

/// Render a nanosecond unix timestamp as `HH:MM:SS` in UTC. Pure
/// arithmetic — avoids pulling chrono just for the feed view. The
/// operator can re-render in their preferred timezone via standard
/// shell tooling (`date -d @TS`) if they care.
fn format_hms_utc(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Render an eta in nanoseconds as "1m 42s" / "23s" / "1h 3m".
/// Matches the format the Twitter image's image uses ("ETA: 1m 42s").
fn format_eta(ns: u64) -> String {
    let total_s = ns / 1_000_000_000;
    if total_s < 60 {
        format!("{total_s}s")
    } else if total_s < 3600 {
        let m = total_s / 60;
        let s = total_s % 60;
        if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m {s}s")
        }
    } else {
        let h = total_s / 3600;
        let m = (total_s % 3600) / 60;
        if m == 0 {
            format!("{h}h")
        } else {
            format!("{h}h {m}m")
        }
    }
}

/// Clamp a comment body to `max` chars + append `…` when truncated.
/// Pure char-boundary aware so we don't slice through a multi-byte
/// codepoint (kanji, emoji).
fn truncate_message(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_PLUGIN_HOSTCALL;

    // ── Band membership ─────────────────────────────────────────────────────

    #[test]
    fn is_kanban_event_covers_full_coding_band() {
        for code in 0x70u8..=0x7F {
            assert!(
                is_kanban_event(code),
                "0x{code:02X} must be classified as a kanban event"
            );
        }
    }

    #[test]
    fn is_kanban_event_rejects_neighbouring_bands() {
        assert!(!is_kanban_event(0x6F), "council band must not bleed in");
        assert!(!is_kanban_event(0x80), "hook band must not bleed in");
        assert!(!is_kanban_event(EVENT_TYPE_PLUGIN_HOSTCALL));
    }

    // ── Parser happy path ───────────────────────────────────────────────────

    #[test]
    fn parse_session_opened_extracts_channel_and_operator() {
        let json = serde_json::json!({
            "session_id": 42,
            "prompt_hash": "deadbeefcafebabe",
            "source_channel": "cli",
            "operator_id": "sam"
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_SESSION_OPENED,
            1_700_000_023_000_000_000,
            json.to_string().as_bytes(),
        )
        .expect("parse session_opened");
        assert_eq!(entry.event_type, EVENT_TYPE_KANBAN_SESSION_OPENED);
        assert_eq!(entry.actor, "system");
        assert!(entry.message.contains("cli"));
        assert!(entry.message.contains("sam"));
    }

    #[test]
    fn parse_task_created_uses_title_and_task_type() {
        let json = serde_json::json!({
            "session_id": 1,
            "task_id": 7,
            "task_type": "ui",
            "title": "Add toggle UI in settings"
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_CREATED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse task_created");
        assert_eq!(entry.actor, "cerebellum");
        assert!(entry.message.contains("Add toggle UI in settings"));
        assert!(entry.message.contains("[ui]"));
    }

    #[test]
    fn parse_task_created_handles_missing_title() {
        let json = serde_json::json!({
            "session_id": 1,
            "task_id": 7,
            "task_type": "ui"
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_CREATED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse with missing title");
        assert!(entry.message.contains("(untitled)"));
    }

    #[test]
    fn parse_task_assigned_includes_worker_and_eta() {
        let json = serde_json::json!({
            "task_id": 7,
            "hemisphere": "left",
            "worker": "local_qwen",
            "eta_ns": 102_000_000_000u64
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_ASSIGNED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse task_assigned");
        assert_eq!(entry.actor, "left");
        assert!(entry.message.contains("local_qwen"));
        assert!(
            entry.message.contains("1m 42s"),
            "ETA 102s must render as `1m 42s`: {}",
            entry.message
        );
    }

    #[test]
    fn parse_task_progress_dispatched_renders_zero_pct_with_hemisphere_actor() {
        // SD-02: the dispatcher's "dispatched" heartbeat (0% on
        // BACKLOG→InProgress) must surface in `neoth kanban watch`.
        let json = serde_json::json!({
            "task_id": 5,
            "session_id": 1,
            "hemisphere": "left",
            "progress_pct": 0,
            "message": "dispatched"
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_PROGRESS,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse task_progress");
        assert_eq!(entry.actor, "left");
        assert!(
            entry.message.starts_with("[░░░░░░░░]"),
            "0% renders an empty bar prefix, got: {}",
            entry.message
        );
        assert!(entry.message.contains("0%"), "got: {}", entry.message);
        assert!(
            entry.message.contains("dispatched"),
            "got: {}",
            entry.message
        );
    }

    #[test]
    fn parse_task_progress_review_ready_renders_100_pct_and_defaults_actor() {
        // 100% review-ready, no hemisphere set → actor falls back to system;
        // no message → bare "100% complete".
        let json = serde_json::json!({
            "task_id": 6,
            "progress_pct": 100
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_PROGRESS,
            200,
            json.to_string().as_bytes(),
        )
        .expect("parse task_progress");
        assert_eq!(entry.actor, "system");
        assert_eq!(entry.message, "[████████] 100% complete");
        assert_eq!(entry.event_type, EVENT_TYPE_KANBAN_TASK_PROGRESS);
    }

    #[test]
    fn progress_bar_renders_filled_proportional_to_pct() {
        assert_eq!(progress_bar(0), "[░░░░░░░░]");
        assert_eq!(progress_bar(50), "[████░░░░]");
        assert_eq!(progress_bar(100), "[████████]");
        // nearest rounding, 12.5% per cell
        assert_eq!(progress_bar(13), "[█░░░░░░░]");
        assert_eq!(progress_bar(6), "[░░░░░░░░]", "6% rounds down to 0 cells");
        // a malformed >100 frame is clamped, never overflows the cell count
        assert_eq!(progress_bar(255), "[████████]");
    }

    #[test]
    fn render_session_summary_blocked_counts_only_no_untrusted_text() {
        use crate::coding::dispatcher::DispatchOutcome;
        let outcome = DispatchOutcome {
            tasks_attempted: 5,
            tasks_completed: 4,
            tasks_blocked: 1,
            ..Default::default()
        };
        let s = render_session_summary(&outcome, 7);
        assert!(
            s.contains("#7"),
            "session summary must include its session identifier"
        );
        assert!(
            s.contains("4/5"),
            "session summary must include completed and attempted counts"
        );
        assert!(
            s.contains("1 blocked"),
            "blocked session summary must include the blocked count"
        );
        assert!(
            s.contains('⚠'),
            "blocked session summary must use the warning icon"
        );
        assert!(
            s.contains('█') || s.contains('░'),
            "session summary must render a progress bar"
        );
    }

    #[test]
    fn render_session_summary_all_done_uses_check_icon() {
        use crate::coding::dispatcher::DispatchOutcome;
        let outcome = DispatchOutcome {
            tasks_attempted: 3,
            tasks_completed: 3,
            ..Default::default()
        };
        let s = render_session_summary(&outcome, 1);
        assert!(
            s.contains('✅'),
            "completed session summary must use the check icon"
        );
        assert!(
            s.contains("3/3"),
            "completed session summary must include completed and attempted counts"
        );
        assert!(
            !s.contains("blocked"),
            "completed session summary must omit the blocked clause"
        );
    }

    #[test]
    fn session_summary_item_is_session_scoped_and_low_priority() {
        use crate::coding::dispatcher::DispatchOutcome;
        let outcome = DispatchOutcome {
            tasks_attempted: 2,
            tasks_completed: 2,
            ..Default::default()
        };
        let item = build_session_summary_item(&outcome, 42);
        assert_eq!(
            item.dedup_key, "coding:session-summary:42",
            "dedup is per-session → at most one summary per session, can't flood the budget"
        );
        assert!(
            item.priority < 50,
            "session summary priority must remain below the reflection-nudge tier"
        );
        assert_eq!(item.source, "coding_session");
        assert_eq!(item.scheduled_for_unix, 0, "drains on the next tick");
        assert!(
            item.body.contains("2/2"),
            "session summary body must include completed and attempted counts"
        );
    }

    #[test]
    fn failed_session_summary_is_urgent_priority_producer() {
        // F37 — a session that ended with blocked tasks is the real
        // URGENT_PRIORITY producer: it early-surfaces (bypasses the schedule).
        use crate::coding::dispatcher::DispatchOutcome;
        let outcome = DispatchOutcome {
            tasks_attempted: 3,
            tasks_completed: 1,
            tasks_blocked: 2,
            ..Default::default()
        };
        let item = build_session_summary_item(&outcome, 7);
        assert!(item.is_failure, "blocked tasks → failure summary");
        assert_eq!(
            item.priority,
            crate::proactive::URGENT_PRIORITY,
            "a failure summary must early-surface at URGENT_PRIORITY"
        );
    }

    #[test]
    fn parse_status_changed_renders_both_states() {
        let json = serde_json::json!({
            "task_id": 7,
            "old_status": "backlog",
            "new_status": "in_progress"
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_STATUS_CHANGED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse status_changed");
        assert!(entry.message.contains("backlog"));
        assert!(entry.message.contains("in_progress"));
        assert!(entry.message.contains("→"));
    }

    #[test]
    fn parse_status_changed_rejects_empty_new_status() {
        // A frame with no `new_status` is malformed — the dispatcher
        // emits one only after the transition succeeded. Skip it
        // rather than print a confusing "Status: backlog → " line.
        let json = serde_json::json!({
            "task_id": 7,
            "old_status": "backlog"
        });
        assert!(
            parse_kanban_payload(
                EVENT_TYPE_KANBAN_STATUS_CHANGED,
                100,
                json.to_string().as_bytes(),
            )
            .is_none(),
            "malformed status_changed frame must surface as None"
        );
    }

    #[test]
    fn parse_task_comment_uses_author_and_truncates_body() {
        let long_body = "x".repeat(200);
        let json = serde_json::json!({
            "task_id": 7,
            "author": "right",
            "body": long_body
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_COMMENT,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse task_comment");
        assert_eq!(entry.actor, "right");
        assert!(
            entry.message.ends_with("…\""),
            "long body must be truncated with ellipsis: {}",
            entry.message
        );
    }

    #[test]
    fn parse_task_completed_summarises_test_outcome() {
        let json = serde_json::json!({
            "task_id": 7,
            "tests_added": 5,
            "tests_passing": 5,
            "tests_failing": 0
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_COMPLETED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse task_completed");
        assert!(entry.message.contains("5 tests added"));
        assert!(entry.message.contains("all passing"));
    }

    #[test]
    fn parse_task_completed_flags_failures() {
        let json = serde_json::json!({
            "task_id": 7,
            "tests_added": 5,
            "tests_passing": 3,
            "tests_failing": 2
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_COMPLETED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse failing");
        assert!(
            entry.message.contains("2 failing"),
            "failing count must surface: {}",
            entry.message,
        );
    }

    #[test]
    fn parse_task_completed_handles_no_tests() {
        let json = serde_json::json!({
            "task_id": 7,
            "tests_added": 0,
            "tests_passing": 0,
            "tests_failing": 0
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_TASK_COMPLETED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse zero-test");
        assert!(
            entry.message.contains("no tests"),
            "zero-test summary must call out the gap: {}",
            entry.message,
        );
    }

    #[test]
    fn parse_session_closed_includes_counts() {
        let json = serde_json::json!({
            "session_id": 1,
            "status": "done",
            "tasks_done": 4,
            "tasks_archived": 1
        });
        let entry = parse_kanban_payload(
            EVENT_TYPE_KANBAN_SESSION_CLOSED,
            100,
            json.to_string().as_bytes(),
        )
        .expect("parse session_closed");
        assert!(entry.message.contains("done"));
        assert!(entry.message.contains("4 done"));
        assert!(entry.message.contains("1 archived"));
    }

    // ── Parser sad path ─────────────────────────────────────────────────────

    #[test]
    fn parse_returns_none_for_non_kanban_event() {
        // A plugin frame happened to land in the same segment — the
        // feed parser MUST decline rather than guess.
        let json = serde_json::json!({"plugin": "x", "kind": "y", "payload_bytes": 1});
        assert!(
            parse_kanban_payload(EVENT_TYPE_PLUGIN_HOSTCALL, 100, json.to_string().as_bytes(),)
                .is_none(),
        );
    }

    #[test]
    fn parse_returns_none_for_corrupt_json() {
        // A truncated / corrupt payload surfaces as None — the
        // operator sees the frame in `neoth wal show` raw but it
        // skips the feed view.
        assert!(
            parse_kanban_payload(EVENT_TYPE_KANBAN_TASK_CREATED, 100, b"{not valid json",)
                .is_none(),
        );
    }

    // ── Formatter ──────────────────────────────────────────────────────────

    #[test]
    fn format_renders_hms_actor_message_columns() {
        let entry = FeedEntry {
            ts_ns: 1_700_000_023_000_000_000,
            event_type: EVENT_TYPE_KANBAN_TASK_COMPLETED,
            actor: "left".to_string(),
            message: "Tests added (5 new)".to_string(),
        };
        let rendered = entry.format();
        // Time should look like HH:MM:SS — pin the format, not the
        // exact value (it depends on what 1.7e18 ns is in UTC).
        assert!(
            rendered.chars().nth(2) == Some(':') && rendered.chars().nth(5) == Some(':'),
            "expected HH:MM:SS prefix, got: {rendered:?}"
        );
        assert!(rendered.contains("left"));
        assert!(rendered.contains("Tests added (5 new)"));
    }

    #[test]
    fn format_hms_utc_handles_known_timestamps() {
        // Unix epoch.
        assert_eq!(format_hms_utc(0), "00:00:00");
        // 12:34:56 UTC after some integer day.
        let ts = 86400u64 * 1_000_000_000
            + 12 * 3600 * 1_000_000_000
            + 34 * 60 * 1_000_000_000
            + 56 * 1_000_000_000;
        assert_eq!(format_hms_utc(ts), "12:34:56");
    }

    #[test]
    fn format_eta_handles_seconds_minutes_hours() {
        assert_eq!(format_eta(23 * 1_000_000_000), "23s");
        assert_eq!(format_eta(60 * 1_000_000_000), "1m");
        assert_eq!(format_eta(102 * 1_000_000_000), "1m 42s");
        assert_eq!(format_eta(3600 * 1_000_000_000), "1h");
        assert_eq!(format_eta((3600 + 180) * 1_000_000_000), "1h 3m");
    }

    #[test]
    fn truncate_message_is_char_boundary_safe() {
        // ASCII — straightforward truncation.
        assert_eq!(truncate_message("abc", 10), "abc");
        assert_eq!(truncate_message("abcdefghijkl", 5), "abcde…");
        // Multi-byte codepoints. A naive `&s[..max]` would panic at
        // a non-boundary; `chars().take(max)` is safe.
        let kanji = "日本語のテスト";
        assert_eq!(kanji.chars().count(), 7);
        let truncated = truncate_message(kanji, 3);
        assert_eq!(truncated.chars().count(), 4); // 3 + ellipsis
        assert!(truncated.ends_with('…'));
    }
}
