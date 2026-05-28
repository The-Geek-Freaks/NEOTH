//! UX-03 — `neoth undo`: show the last N state-mutating WAL frames +
//! how to reverse each.
//!
//! NEOTH's WAL is append-only + event-sourced: the materialised views
//! (`idx_*`) are a replay of the frame stream. "Undo" therefore is NOT
//! an in-place edit of the WAL — it's either re-applying a prior state
//! (e.g. the previous preset) or appending a compensating frame. This
//! command is the **discovery half**: it scans the WAL, lists the most
//! recent mutating frames with timestamps + a human description, and —
//! crucially — the CONCRETE existing command to reverse each one. So a
//! fresh operator who just did something they regret can see "here's
//! what changed + here's the exact command to walk it back".
//!
//! Reverse-hints only ever name commands that actually exist (no
//! fictional auto-reverser): preset re-apply, profile redact/unredact,
//! kanban status moves, etc. The confirm-gated AUTO-reverser
//! (`neoth undo apply <n>`) is a deliberate follow-up: reversing
//! arbitrary materialised state safely needs a per-frame-type
//! compensating-frame design + view re-index, which is destructive and
//! gets its own focused pass. Listing first keeps this increment safe.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::events;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::SEGMENT_HEADER_LEN;

#[derive(Args, Debug, Clone)]
pub struct UndoArgs {
    /// How many recent mutating frames to show (newest at the bottom).
    #[arg(long, default_value = "5")]
    pub limit: usize,

    /// Override the WAL directory (default `~/.neoth/wal`). Mainly for
    /// tests + operators with a relocated WAL.
    #[arg(long)]
    pub wal_dir: Option<PathBuf>,

    #[arg(skip)]
    pub output: OutputFormat,
}

/// How (if at all) a mutating frame can be walked back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversal {
    /// A concrete existing command reverses it (see `reverse_hint`).
    Command,
    /// Reversible, but the operator drives it through an external tool
    /// (e.g. `git` in the task worktree for an applied patch).
    Manual,
    /// Audit/decision record — reversing it would falsify the trail;
    /// surfaced for visibility only.
    AuditOnly,
}

impl Reversal {
    pub fn label(self) -> &'static str {
        match self {
            Reversal::Command => "reversible",
            Reversal::Manual => "manual",
            Reversal::AuditOnly => "audit-only",
        }
    }
}

/// One mutating frame as shown by `neoth undo`.
#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub ts_ns: u64,
    pub event_type: u8,
    pub name: &'static str,
    pub reversal: Reversal,
    /// Operator-readable description of what the frame did.
    pub what: &'static str,
    /// Concrete command / step to reverse it (empty for AuditOnly).
    pub reverse_hint: &'static str,
}

/// Classify a WAL event type as a reversible mutation. `None` ⇒ the
/// event isn't an operator-facing state mutation (telemetry, request
/// lifecycle, refusal detectors, …) so `neoth undo` skips it.
///
/// Every `reverse_hint` names a command/tool that ACTUALLY exists —
/// no fictional auto-reverser. Kept as a small explicit table rather
/// than a band-range so adding a new mutating event is a deliberate
/// one-line decision about how it's reversed.
pub fn classify(event_type: u8) -> Option<(&'static str, Reversal, &'static str, &'static str)> {
    // (name, reversal, what, reverse_hint)
    let row = match event_type {
        events::EVENT_TYPE_PROFILE_PRESET_APPLIED => (
            "PROFILE_PRESET_APPLIED",
            Reversal::Command,
            "switched the active behavioural preset",
            "re-apply the previous one: `neoth profile preset apply <name>`",
        ),
        events::EVENT_TYPE_PROFILE_DELTA => (
            "PROFILE_DELTA",
            Reversal::Command,
            "wrote/updated a profile claim",
            "redact the field: `neoth profile redact <field>`",
        ),
        events::EVENT_TYPE_PROFILE_DELTA_APPROVED => (
            "PROFILE_DELTA_APPROVED",
            Reversal::Command,
            "approved a pending profile claim into the profile",
            "redact the field: `neoth profile redact <field>`",
        ),
        events::EVENT_TYPE_REDACTION_MARKER => (
            "REDACTION_MARKER",
            Reversal::Command,
            "marked a profile field never-recreate (redaction)",
            "revoke it: `neoth profile unredact --id <id>`",
        ),
        events::EVENT_TYPE_GROUNDTRUTH_ADDED => (
            "GROUNDTRUTH_ADDED",
            Reversal::Command,
            "added a ground-truth assertion",
            "revoke via the ground-truth CLI (`neoth groundtruth`)",
        ),
        events::EVENT_TYPE_GROUNDTRUTH_IMPORTED => (
            "GROUNDTRUTH_IMPORTED",
            Reversal::Command,
            "bulk-imported ground-truth assertions",
            "revoke the imported rows via `neoth groundtruth`",
        ),
        events::EVENT_TYPE_KANBAN_TASK_CREATED => (
            "KANBAN_TASK_CREATED",
            Reversal::Command,
            "created a coding-workflow kanban task",
            "move/close it via the `neoth kanban` family",
        ),
        events::EVENT_TYPE_KANBAN_TASK_COMPLETED => (
            "KANBAN_TASK_COMPLETED",
            Reversal::Command,
            "marked a kanban task done",
            "reopen/move it via the `neoth kanban` family",
        ),
        events::EVENT_TYPE_PATCH_APPLIED => (
            "PATCH_APPLIED",
            Reversal::Manual,
            "applied a worker patch into a task git worktree",
            "revert in the worktree: `git -C <worktree> apply -R <patch>` (or drop the worktree)",
        ),
        events::EVENT_TYPE_SELF_DEV_ACCEPTED => (
            "SELF_DEV_ACCEPTED",
            Reversal::AuditOnly,
            "accepted a self-development proposal",
            "",
        ),
        events::EVENT_TYPE_CONSENT_DECISION => (
            "CONSENT_DECISION",
            Reversal::AuditOnly,
            "recorded an operator consent decision",
            "",
        ),
        events::EVENT_TYPE_GROUNDTRUTH_REVOKED => (
            "GROUNDTRUTH_REVOKED",
            Reversal::AuditOnly,
            "revoked a ground-truth assertion (already a reversal)",
            "",
        ),
        _ => return None,
    };
    Some(row)
}

/// Walk every `.wal` segment in `wal_dir`, decode frames, keep the
/// mutating ones, and return the last `limit` sorted by timestamp
/// ascending (freshest at the bottom — `tail` muscle memory, matching
/// `neoth kanban watch`). Pure of side effects; bad frames are skipped
/// (operators use `neoth wal verify` to surface corruption).
pub fn scan_wal_dir_for_undo(wal_dir: &PathBuf, limit: usize) -> Result<Vec<UndoEntry>> {
    if !wal_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<UndoEntry> = Vec::new();
    let read_dir =
        std::fs::read_dir(wal_dir).with_context(|| format!("read_dir {}", wal_dir.display()))?;
    let mut segments: Vec<PathBuf> = read_dir
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x == "wal")
        })
        .map(|e| e.path())
        .collect();
    segments.sort();
    for seg in &segments {
        if let Ok(bytes) = std::fs::read(seg) {
            scan_segment_bytes(&bytes, &mut entries);
        }
    }
    entries.sort_by_key(|e| e.ts_ns);
    let total = entries.len();
    if total > limit {
        entries.drain(0..total - limit);
    }
    Ok(entries)
}

fn scan_segment_bytes(bytes: &[u8], out: &mut Vec<UndoEntry>) {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return;
    }
    let mut cursor = SEGMENT_HEADER_LEN;
    while cursor < bytes.len() {
        match decode_frame(&bytes[cursor..]) {
            Ok(dec) => {
                let total = dec.header.total_len as usize;
                if total == 0 {
                    break;
                }
                if let Some((name, reversal, what, reverse_hint)) = classify(dec.header.event_type)
                {
                    out.push(UndoEntry {
                        ts_ns: dec.header.hlc.physical_ns(),
                        event_type: dec.header.event_type,
                        name,
                        reversal,
                        what,
                        reverse_hint,
                    });
                }
                cursor += total;
            }
            Err(_) => break,
        }
    }
}

fn format_ts_short(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// `neoth undo` entry point. Read-only.
pub fn run_undo(args: UndoArgs) -> Result<()> {
    let wal_dir = args.wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);
    let entries = scan_wal_dir_for_undo(&wal_dir, args.limit)?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "ts_unix": e.ts_ns / 1_000_000_000,
                        "event_type": format!("0x{:02X}", e.event_type),
                        "name": e.name,
                        "reversal": e.reversal.label(),
                        "what": e.what,
                        "reverse_hint": e.reverse_hint,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".to_string())
            );
        }
        OutputFormat::Table => {
            if entries.is_empty() {
                println!(
                    "No mutating frames in {} — nothing to undo.",
                    wal_dir.display()
                );
                return Ok(());
            }
            println!(
                "Last {} state-mutating change(s) — freshest at the bottom:\n",
                entries.len()
            );
            for (i, e) in entries.iter().enumerate() {
                println!(
                    "  [{n}] {ts}  {name:<24} {tag}",
                    n = i + 1,
                    ts = format_ts_short(e.ts_ns),
                    name = e.name,
                    tag = e.reversal.label(),
                );
                println!("       {}", e.what);
                if !e.reverse_hint.is_empty() {
                    println!("       ↩ {}", e.reverse_hint);
                }
            }
            println!(
                "\nThese are the existing ways to walk each change back. A confirm-gated\n\
                 auto-reverser (`neoth undo apply <n>`) is a separate, deliberate step."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_mutations_and_skips_others() {
        // A reversible-by-command mutation.
        let (name, rev, _, hint) =
            classify(events::EVENT_TYPE_PROFILE_PRESET_APPLIED).expect("preset is mutating");
        assert_eq!(name, "PROFILE_PRESET_APPLIED");
        assert_eq!(rev, Reversal::Command);
        assert!(hint.contains("neoth profile preset apply"));

        // A manual (external-tool) reversal.
        let (_, rev, _, hint) =
            classify(events::EVENT_TYPE_PATCH_APPLIED).expect("patch is mutating");
        assert_eq!(rev, Reversal::Manual);
        assert!(hint.contains("git"));

        // An audit-only frame carries no reverse hint.
        let (_, rev, _, hint) =
            classify(events::EVENT_TYPE_CONSENT_DECISION).expect("consent is listed");
        assert_eq!(rev, Reversal::AuditOnly);
        assert!(hint.is_empty());

        // A non-mutating event (raw text) is skipped entirely.
        assert!(classify(events::EVENT_TYPE_RAW_TEXT).is_none());
    }

    #[test]
    fn reverse_hints_name_no_fictional_command() {
        // Anti-hallucination guard: the only `neoth …` commands the
        // hints reference must be ones that exist. We assert the
        // command roots are from the known set.
        for code in [
            events::EVENT_TYPE_PROFILE_PRESET_APPLIED,
            events::EVENT_TYPE_PROFILE_DELTA,
            events::EVENT_TYPE_REDACTION_MARKER,
            events::EVENT_TYPE_KANBAN_TASK_CREATED,
        ] {
            let (_, _, _, hint) = classify(code).unwrap();
            assert!(
                hint.contains("neoth profile") || hint.contains("neoth kanban"),
                "hint must reference a real command family: {hint}"
            );
        }
    }

    #[test]
    fn scan_missing_dir_returns_empty() {
        let dir = PathBuf::from("/nonexistent/neoth/wal/path/xyz");
        assert!(scan_wal_dir_for_undo(&dir, 5).unwrap().is_empty());
    }

    #[test]
    fn format_ts_short_is_hhmmss() {
        // 1 hour + 2 minutes + 3 seconds past a UTC day boundary.
        let ts = (3600 + 120 + 3) * 1_000_000_000u64;
        assert_eq!(format_ts_short(ts), "01:02:03");
    }
}
