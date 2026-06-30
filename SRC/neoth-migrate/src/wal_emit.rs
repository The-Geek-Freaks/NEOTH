//! WAL audit sidecar for `neoth-migrate apply`.
//!
//! `neoth-migrate` is a standalone binary; it cannot hold the daemon's
//! `WalWriterHandle` (single-writer invariant). Instead it writes a JSONL
//! audit file at `~/.neoth/neoth-migrate-audit.jsonl` using three lifecycle
//! events:
//!
//! | kind | when |
//! |---|---|
//! | `MIGRATION_STARTED` | before the source loop |
//! | `MIGRATION_BATCH` | after each source is processed |
//! | `MIGRATION_COMPLETE` | after `COMMIT` succeeds |
//!
//! The file is appended-to (not truncated) so repeated runs accumulate a
//! full history. All writes are best-effort: a filesystem error is silently
//! ignored so that a read-only `.neoth` dir never causes the import to abort.
//!
//! The `GROUNDTRUTH_IMPORTED` (0x99) summary line previously written inline
//! in `run_apply` is now replaced by `MIGRATION_COMPLETE`.  Existing tooling
//! that parsed `GROUNDTRUTH_IMPORTED` should use `MIGRATION_COMPLETE` instead;
//! both fields (`inserted`, `sources_total`) are present.

use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Writes structured JSONL audit events to `~/.neoth/neoth-migrate-audit.jsonl`.
///
/// Constructed once per `run_apply` invocation **after** the dry-run early
/// return and **after** the schema check, so no events are written on
/// dry-run paths or schema failures.
///
/// When `dry_run` is `true`, all `emit_*` calls are no-ops (the guard is
/// belt-and-suspenders; the caller should never reach the emitter on a
/// dry-run path).
pub struct OperatorWalEmitter {
    audit_path: PathBuf,
    dry_run: bool,
}

impl OperatorWalEmitter {
    /// Create a new emitter targeting `<home>/.neoth/neoth-migrate-audit.jsonl`.
    ///
    /// Pass `dry_run: true` to disable all writes (no-op emitter).
    pub fn new(home: &Path, dry_run: bool) -> Self {
        Self {
            audit_path: home.join(".neoth").join("neoth-migrate-audit.jsonl"),
            dry_run,
        }
    }

    /// Emit `MIGRATION_STARTED` — called once before the source loop.
    pub fn emit_migration_started(&self, sources_total: usize) {
        if self.dry_run {
            return;
        }
        let line = serde_json::json!({
            "kind": "MIGRATION_STARTED",
            "sources_total": sources_total,
            "ts_ns": now_ns(),
        });
        self.append_line(&line);
    }

    /// Emit `MIGRATION_BATCH` — called once per source after its claims
    /// have been processed (whether inserted or skipped due to duplicates).
    ///
    /// `claims_seen` is the total number of `(statement, source_tag, scope)`
    /// tuples returned by `emit_claims` for this source.  `inserted` is the
    /// count that actually hit the database (i.e. were not duplicates).
    pub fn emit_migration_batch(&self, source_name: &str, claims_seen: usize, inserted: usize) {
        if self.dry_run {
            return;
        }
        let line = serde_json::json!({
            "kind": "MIGRATION_BATCH",
            "source_name": source_name,
            "claims_seen": claims_seen,
            "inserted": inserted,
            "skipped_duplicates": claims_seen.saturating_sub(inserted),
            "ts_ns": now_ns(),
        });
        self.append_line(&line);
    }

    /// Emit `MIGRATION_COMPLETE` — called once after `COMMIT` succeeds.
    ///
    /// Also includes the legacy `event`/`event_type` fields so that
    /// tooling that previously parsed `GROUNDTRUTH_IMPORTED` (0x99) can
    /// detect this line via either field.
    pub fn emit_migration_complete(&self, inserted: usize, skipped_sources: usize) {
        if self.dry_run {
            return;
        }
        let line = serde_json::json!({
            "kind": "MIGRATION_COMPLETE",
            // Legacy compat: tools that parsed the old single-line summary
            // by "event"/"event_type" will still match.
            "event": "GROUNDTRUTH_IMPORTED",
            "event_type": 0x99u8,   // = 153
            "inserted": inserted,
            "skipped_sources": skipped_sources,
            "ts_ns": now_ns(),
        });
        self.append_line(&line);
    }

    // ── private ───────────────────────────────────────────────────────────────

    fn append_line(&self, value: &serde_json::Value) {
        // Best-effort: silently ignore any I/O error so a read-only
        // ~/.neoth dir does not abort the import.
        if let Ok(serialised) = serde_json::to_string(value) {
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.audit_path)
                .and_then(|mut f| writeln!(f, "{serialised}"));
        }
    }
}

/// Current wall-clock time in nanoseconds since the Unix epoch.
fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSON line"))
            .collect()
    }

    #[test]
    fn emits_three_lifecycle_events_in_order() {
        let dir = tempdir().unwrap();
        let emitter = OperatorWalEmitter::new(dir.path(), false);
        let audit = dir.path().join(".neoth").join("neoth-migrate-audit.jsonl");
        std::fs::create_dir_all(dir.path().join(".neoth")).unwrap();

        emitter.emit_migration_started(2);
        emitter.emit_migration_batch("src-a", 3, 3);
        emitter.emit_migration_batch("src-b", 1, 0);
        emitter.emit_migration_complete(3, 0);

        let lines = read_jsonl(&audit);
        assert_eq!(lines.len(), 4, "expected 4 JSONL lines");

        assert_eq!(lines[0]["kind"], "MIGRATION_STARTED");
        assert_eq!(lines[0]["sources_total"], 2);

        assert_eq!(lines[1]["kind"], "MIGRATION_BATCH");
        assert_eq!(lines[1]["source_name"], "src-a");
        assert_eq!(lines[1]["inserted"], 3);

        assert_eq!(lines[2]["kind"], "MIGRATION_BATCH");
        assert_eq!(lines[2]["source_name"], "src-b");
        assert_eq!(lines[2]["inserted"], 0);
        assert_eq!(lines[2]["skipped_duplicates"], 1);

        assert_eq!(lines[3]["kind"], "MIGRATION_COMPLETE");
        assert_eq!(lines[3]["inserted"], 3);
        assert_eq!(lines[3]["skipped_sources"], 0);
        // Legacy compat fields
        assert_eq!(lines[3]["event"], "GROUNDTRUTH_IMPORTED");
        assert_eq!(lines[3]["event_type"], 153);
    }

    #[test]
    fn dry_run_mode_writes_no_lines() {
        let dir = tempdir().unwrap();
        let emitter = OperatorWalEmitter::new(dir.path(), /* dry_run= */ true);
        std::fs::create_dir_all(dir.path().join(".neoth")).unwrap();

        emitter.emit_migration_started(1);
        emitter.emit_migration_batch("x", 5, 5);
        emitter.emit_migration_complete(5, 0);

        let audit = dir.path().join(".neoth").join("neoth-migrate-audit.jsonl");
        assert!(
            !audit.exists(),
            "dry_run emitter must not create the audit file"
        );
    }

    #[test]
    fn missing_neoth_dir_does_not_panic() {
        // .neoth dir does NOT exist — append_line must silently swallow the error.
        let dir = tempdir().unwrap();
        let emitter = OperatorWalEmitter::new(dir.path(), false);
        // No create_dir_all here on purpose.
        emitter.emit_migration_started(0);
        emitter.emit_migration_complete(0, 0);
        // If we reach here without panic, the test passes.
    }

    #[test]
    fn skipped_sources_counted_in_complete() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".neoth")).unwrap();
        let emitter = OperatorWalEmitter::new(dir.path(), false);
        let audit = dir.path().join(".neoth").join("neoth-migrate-audit.jsonl");

        emitter.emit_migration_started(3);
        emitter.emit_migration_batch("ok-src", 10, 10);
        // Two sources skipped (emit_claims failed) — no BATCH emitted for them.
        emitter.emit_migration_complete(10, 2);

        let lines = read_jsonl(&audit);
        // STARTED + one BATCH + COMPLETE
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2]["skipped_sources"], 2);
    }
}
