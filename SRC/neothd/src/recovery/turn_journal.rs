//! R-01 (Session 24) — Turn-Journal write-ahead JSONL for `neoth chat`
//! mid-stream durability.
//!
//! ## Why
//!
//! The main WAL is a binary, append-only audit chain. It's optimized
//! for the long-haul record — every frame's content gets HMAC'd into
//! the running chain at compaction time, payloads are dedup'd by
//! `text_hash`, indexes downstream of the WAL assume the bytes never
//! change. That's the right shape for an audit log.
//!
//! But mid-stream chat is different: an in-flight provider call can
//! produce streaming chunks the operator wants to NOT lose if the
//! daemon crashes between `provider.send_request()` and the final
//! `provider_response` frame. Encoding every partial-chunk into the
//! main WAL would bloat the audit chain with mostly-redundant data
//! (the final response supersedes the chunks for replay).
//!
//! The turn-journal solves that by living OUTSIDE the WAL in a
//! sidecar JSONL file at `~/.neoth/journals/<turn_id>.jsonl`. Each
//! line is one `{event: "...", ts_ns: ..., ...}` record. On clean
//! turn completion the file is deleted. A journal sitting on disk
//! at next launch = the previous run crashed mid-turn → operator
//! recovery candidate.
//!
//! WAL anchors:
//! - `EVENT_TYPE_TURN_JOURNAL_OPENED` (0x05) is appended to the
//!   main WAL when the journal is created.
//! - `EVENT_TYPE_TURN_JOURNAL_CLOSED` (0x06) is appended on
//!   clean completion. The audit chain therefore answers "which
//!   turns survived their window cleanly" without needing to know
//!   any sidecar file content.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Subdirectory under `~/.neoth/` where active turn journals live.
pub const JOURNAL_DIR: &str = "journals";

/// One in-flight turn journal. Constructed via [`TurnJournal::open`];
/// drop deletes the file IF [`TurnJournal::close`] was called, otherwise
/// leaves the file on disk for the recovery path to find.
#[derive(Debug)]
pub struct TurnJournal {
    turn_id: String,
    path: PathBuf,
    /// When true, [`Drop`] removes the file. Set by [`close`].
    finished: bool,
}

impl TurnJournal {
    /// Open a fresh journal for `turn_id`. Creates the parent dir if
    /// missing. Operator-supplied `turn_id` must be filesystem-safe;
    /// callers typically pass the chat's `event_id` formatted as
    /// `0x{:016x}` so collisions can't happen across turns.
    pub fn open(neoth_dir: &Path, turn_id: impl Into<String>) -> Result<Self> {
        let turn_id = turn_id.into();
        if turn_id.is_empty()
            || turn_id.contains('/')
            || turn_id.contains('\\')
            || turn_id.contains("..")
        {
            anyhow::bail!(
                "turn_id `{turn_id}` is not a safe filename component (rejected: empty / slash / parent-traversal)"
            );
        }
        let journal_dir = neoth_dir.join(JOURNAL_DIR);
        std::fs::create_dir_all(&journal_dir)
            .with_context(|| format!("create journal dir {}", journal_dir.display()))?;
        let path = journal_dir.join(format!("{turn_id}.jsonl"));
        // Truncate-on-open: a stale file from a prior aborted-mid-write
        // run shouldn't poison the new turn's history.
        std::fs::write(&path, b"")
            .with_context(|| format!("create journal file {}", path.display()))?;
        Ok(Self {
            turn_id,
            path,
            finished: false,
        })
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a single event line. The serialised object MUST fit on
    /// one JSONL line — multi-line payloads break the recovery
    /// reader's line-at-a-time scan. Use compact `serde_json::to_string`
    /// (not pretty) for the value.
    pub fn append(&mut self, event: &TurnEvent) -> Result<()> {
        let body = serde_json::to_string(event).context("serialise turn event")?;
        if body.contains('\n') {
            anyhow::bail!("turn event payload must not contain newlines");
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open journal {}", self.path.display()))?;
        writeln!(f, "{body}").with_context(|| format!("append to {}", self.path.display()))?;
        Ok(())
    }

    /// Mark the turn clean + delete the file. Idempotent — calling
    /// twice is a no-op on the second call. After `close` the
    /// journal can no longer accept appends.
    pub fn close(mut self) -> Result<()> {
        self.finished = true;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context(format!("remove {}", self.path.display())),
        }
    }
}

impl Drop for TurnJournal {
    fn drop(&mut self) {
        // Crash path: leave the file on disk for the recovery scan to find.
        // Clean path: close() already removed it.
        if self.finished {
            // close() already handled deletion; nothing to do.
            return;
        }
        // Best-effort flush via close-on-drop semantics — the file
        // handle was already dropped at the end of the last `append`
        // call so the bytes are on disk modulo OS cache.
    }
}

/// One line in a turn journal. Operator-facing — a future log-viewer
/// reads these as a chronological narrative of "what was the chat
/// doing when it crashed".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum TurnEvent {
    /// Captured when the journal opens. Mirrors the WAL
    /// `EVENT_TYPE_TURN_JOURNAL_OPENED` payload.
    Started {
        ts_unix: i64,
        prompt_excerpt: String,
    },
    /// One provider call dispatched.
    ProviderRequest {
        ts_unix: i64,
        provider: String,
        model: String,
    },
    /// One streamed chunk arrived from the provider. Operator-side
    /// recovery can replay these in order to show a partial answer.
    ProviderChunk { ts_unix: i64, text: String },
    /// Provider call completed (success).
    ProviderResponse {
        ts_unix: i64,
        provider: String,
        model: String,
        input_tokens: u32,
        output_tokens: u32,
    },
    /// Provider call errored — used for crash forensics.
    ProviderError { ts_unix: i64, error: String },
}

/// One in-flight or orphaned journal discovered by [`scan_for_journals`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct JournalReport {
    pub turn_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub line_count: usize,
}

/// Walk `~/.neoth/journals/` for `*.jsonl` files. Each surviving file
/// is an orphan: the previous turn crashed before `close` could
/// delete it. R-06's CLI consumes this list alongside `BakReport`s.
pub fn scan_for_journals(neoth_dir: &Path) -> Result<Vec<JournalReport>> {
    let journal_dir = neoth_dir.join(JOURNAL_DIR);
    let entries = match std::fs::read_dir(&journal_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context(format!("read_dir {}", journal_dir.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        let Some(turn_id) = name.strip_suffix(".jsonl") else {
            continue;
        };
        let size_bytes = entry.metadata()?.len();
        let line_count = match std::fs::read_to_string(&path) {
            Ok(body) => body.lines().filter(|l| !l.is_empty()).count(),
            Err(_) => 0,
        };
        out.push(JournalReport {
            turn_id: turn_id.to_string(),
            path,
            size_bytes,
            line_count,
        });
    }
    out.sort_by(|a, b| a.turn_id.cmp(&b.turn_id));
    Ok(out)
}

/// Build the canonical OPENED-frame payload bytes for the WAL writer.
/// Pure helper so the chat dispatch + the test path agree on shape.
pub fn opened_payload(turn_id: &str, journal_path: &Path, ts_unix: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "turn_id": turn_id,
        "journal_path": journal_path.display().to_string(),
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// Build the canonical CLOSED-frame payload bytes.
pub fn closed_payload(turn_id: &str, ts_unix: i64, line_count: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "turn_id": turn_id,
        "ts_unix": ts_unix,
        "line_count": line_count,
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_creates_empty_journal_file_in_journal_dir() {
        let dir = tempdir().unwrap();
        let j = TurnJournal::open(dir.path(), "turn-001").unwrap();
        assert_eq!(j.turn_id(), "turn-001");
        assert!(j.path().exists());
        assert!(j.path().starts_with(dir.path().join(JOURNAL_DIR)));
        let body = std::fs::read_to_string(j.path()).unwrap();
        assert!(body.is_empty(), "fresh journal must be empty");
    }

    #[test]
    fn open_rejects_unsafe_turn_ids() {
        let dir = tempdir().unwrap();
        for bad in &["", "../etc/passwd", "x/y", "a\\b", "with..dots"] {
            let r = TurnJournal::open(dir.path(), *bad);
            assert!(r.is_err(), "must reject `{bad}`");
        }
    }

    #[test]
    fn append_writes_one_jsonl_line_per_call() {
        let dir = tempdir().unwrap();
        let mut j = TurnJournal::open(dir.path(), "turn-002").unwrap();
        j.append(&TurnEvent::Started {
            ts_unix: 100,
            prompt_excerpt: "hello".into(),
        })
        .unwrap();
        j.append(&TurnEvent::ProviderRequest {
            ts_unix: 101,
            provider: "claude_cli".into(),
            model: "claude-opus-4-7".into(),
        })
        .unwrap();
        let body = std::fs::read_to_string(j.path()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is parseable JSON with the tag discriminator.
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("event").is_some());
            assert!(parsed.get("ts_unix").is_some());
        }
    }

    #[test]
    fn close_deletes_the_journal_file() {
        let dir = tempdir().unwrap();
        let j = TurnJournal::open(dir.path(), "turn-003").unwrap();
        let path = j.path().to_path_buf();
        assert!(path.exists());
        j.close().unwrap();
        assert!(!path.exists(), "close must delete the file");
    }

    #[test]
    fn close_is_idempotent_when_file_already_gone() {
        // Edge case: an external process removed the journal between
        // append + close. close must succeed instead of crashing the
        // shutdown path.
        let dir = tempdir().unwrap();
        let j = TurnJournal::open(dir.path(), "turn-004").unwrap();
        std::fs::remove_file(j.path()).unwrap();
        j.close().unwrap();
    }

    #[test]
    fn drop_without_close_leaves_file_on_disk() {
        // The recovery contract: a journal that hits Drop without
        // being closed = crash mid-turn = the file MUST survive.
        let dir = tempdir().unwrap();
        let path = {
            let j = TurnJournal::open(dir.path(), "turn-005").unwrap();
            let p = j.path().to_path_buf();
            // Drop without calling close — simulates a crash.
            drop(j);
            p
        };
        assert!(path.exists(), "Drop must leave the journal file on disk");
    }

    #[test]
    fn scan_returns_empty_for_missing_journal_dir() {
        let dir = tempdir().unwrap();
        let reports = scan_for_journals(dir.path()).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn scan_surfaces_orphan_journals_with_line_count() {
        let dir = tempdir().unwrap();
        let mut j = TurnJournal::open(dir.path(), "alpha").unwrap();
        j.append(&TurnEvent::Started {
            ts_unix: 1,
            prompt_excerpt: "x".into(),
        })
        .unwrap();
        j.append(&TurnEvent::ProviderRequest {
            ts_unix: 2,
            provider: "p".into(),
            model: "m".into(),
        })
        .unwrap();
        // Drop without close — orphan.
        drop(j);

        // Second journal that survived clean (file gone).
        let clean = TurnJournal::open(dir.path(), "beta").unwrap();
        clean.close().unwrap();

        let reports = scan_for_journals(dir.path()).unwrap();
        assert_eq!(reports.len(), 1, "only the orphan should surface");
        assert_eq!(reports[0].turn_id, "alpha");
        assert_eq!(reports[0].line_count, 2);
        assert!(reports[0].size_bytes > 0);
    }

    #[test]
    fn scan_skips_non_jsonl_files_in_journal_dir() {
        let dir = tempdir().unwrap();
        let jd = dir.path().join(JOURNAL_DIR);
        std::fs::create_dir_all(&jd).unwrap();
        std::fs::write(jd.join("README.md"), b"not a journal").unwrap();
        std::fs::write(
            jd.join("real.jsonl"),
            b"{\"event\":\"Started\",\"ts_unix\":1,\"prompt_excerpt\":\"x\"}\n",
        )
        .unwrap();
        let reports = scan_for_journals(dir.path()).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].turn_id, "real");
    }

    #[test]
    fn opened_payload_is_canonical_json_with_required_fields() {
        let bytes = opened_payload("turn-abc", Path::new("/x/y.jsonl"), 1700);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["turn_id"], "turn-abc");
        assert_eq!(v["ts_unix"], 1700);
        assert!(v["journal_path"].as_str().unwrap().contains("y.jsonl"));
    }

    #[test]
    fn closed_payload_carries_line_count() {
        let bytes = closed_payload("turn-abc", 1800, 42);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["turn_id"], "turn-abc");
        assert_eq!(v["line_count"], 42);
    }

    #[test]
    fn append_escapes_newlines_via_serde_so_each_event_stays_on_one_line() {
        // Defensive: any operator-controlled text in a TurnEvent
        // variant (e.g. ProviderChunk.text) must NOT smuggle a raw
        // newline through and break the line-at-a-time recovery
        // scan. serde_json escapes newlines to the two-char `\n`
        // sequence; the in-module `body.contains('\n')` guard catches
        // anything that bypassed serde_json (currently unreachable
        // via the public API but pinned defensively).
        let dir = tempdir().unwrap();
        let mut j = TurnJournal::open(dir.path(), "newline-pin").unwrap();
        let chunk = TurnEvent::ProviderChunk {
            ts_unix: 1,
            text: "first\nsecond\nthird".into(),
        };
        j.append(&chunk)
            .expect("serde escape keeps the line intact");
        let body = std::fs::read_to_string(j.path()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one line per event, got: {body:?}");
        // The escaped sequence appears as `\\n` in the rust string
        // literal (i.e. two bytes: backslash + n) inside the JSON.
        assert!(
            lines[0].contains("\\n"),
            "newlines must be escaped, not raw: {}",
            lines[0],
        );
        // Round-trips back to the original raw text.
        let parsed: TurnEvent = serde_json::from_str(lines[0]).unwrap();
        if let TurnEvent::ProviderChunk { text, .. } = parsed {
            assert_eq!(text, "first\nsecond\nthird");
        } else {
            panic!("wrong variant after round-trip");
        }
    }
}
