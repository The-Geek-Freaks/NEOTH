//! KF-10 — Structured-Forgetting Export.
//!
//! Just before the consolidation pass DELETEs a hot-tier memory that has
//! fallen below `FORGET_FLOOR` (forgotten forever — not promoted to warm
//! or long-term), this module drafts a frontmatter-markdown summary of it
//! into the operator's Obsidian vault under `PreDecay/`. The operator
//! gets a last-chance, human-readable record of what NEOTH is about to
//! forget — they can review the drafts, and salvage anything worth
//! keeping into a permanent note before the next sweep.
//!
//! ## Why capture-before-delete (not a re-query)
//!
//! The set of rows that get forgotten is decided by the consolidation
//! loop itself (`importance < FORGET_FLOOR` AND `ts_ns < now - 7d`). This
//! module is fed EXACTLY those rows, captured inline at the delete site,
//! rather than re-deriving the criterion here — a re-query could drift
//! from the real deletion predicate and export the wrong set (or miss
//! rows). [`PreDecayRow`] is the captured shape.
//!
//! ## Safety
//!
//! - File IO happens AFTER the SQLite transaction commits, never inside
//!   it — a slow/failing vault write can't hold the DB lock or roll back
//!   a decay pass.
//! - Best-effort per file: one failed write is logged + skipped; the
//!   others still land. A decay pass must NEVER fail because Obsidian is
//!   on a full or read-only disk.
//! - Atomic per file: write to `<name>.md.tmp` then rename, so a crash
//!   mid-write never leaves a half-written note Obsidian would index.
//! - `event_id` is an `i64`, so the filename carries no operator- or
//!   attacker-controlled path component — no traversal surface.

use std::path::Path;

/// One hot-tier memory about to be forgotten, captured at the delete
/// site in [`super::consolidate::run_consolidation_pass`].
#[derive(Debug, Clone, PartialEq)]
pub struct PreDecayRow {
    pub event_id: i64,
    pub ts_ns: i64,
    pub text: String,
    pub importance: f64,
}

/// Write one frontmatter-markdown draft per row into `<vault>/PreDecay/`.
/// Returns the number of files actually written (best-effort: failures
/// are logged + skipped, not propagated). A no-op returning `0` when
/// `rows` is empty. Creates `<vault>/PreDecay/` if absent.
pub fn write_pre_decay_drafts(vault: &Path, rows: &[PreDecayRow]) -> usize {
    if rows.is_empty() {
        return 0;
    }
    let dir = vault.join("PreDecay");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "pre-decay export: could not create PreDecay dir; skipping this pass"
        );
        return 0;
    }
    let mut written = 0usize;
    for row in rows {
        let day = day_string(row.ts_ns);
        let name = format!("{day}-{}.md", row.event_id);
        let final_path = dir.join(&name);
        let tmp_path = dir.join(format!("{name}.tmp"));
        let body = render_draft(row);
        // Atomic: write tmp, then rename over the final name.
        match std::fs::write(&tmp_path, body.as_bytes()) {
            Ok(()) => match std::fs::rename(&tmp_path, &final_path) {
                Ok(()) => written += 1,
                Err(e) => {
                    tracing::warn!(
                        path = %final_path.display(),
                        error = %e,
                        "pre-decay export: rename failed; draft skipped"
                    );
                    let _ = std::fs::remove_file(&tmp_path);
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %tmp_path.display(),
                    error = %e,
                    "pre-decay export: write failed; draft skipped"
                );
            }
        }
    }
    written
}

/// Render one pre-decay row as Obsidian frontmatter markdown. The
/// frontmatter keys are stable (operators may build Dataview queries over
/// them); the body is the verbatim memory text.
fn render_draft(row: &PreDecayRow) -> String {
    let day = day_string(row.ts_ns);
    let iso = iso_string(row.ts_ns);
    // YAML-escape the text only where it appears in frontmatter (it does
    // not — text is the body), so the body is verbatim. The frontmatter
    // carries only numeric + ISO-date scalars, which need no quoting.
    format!(
        "---\nevent_id: {}\nts_ns: {}\nts: {}\nday: {}\nimportance: {}\nsource: neoth-pre-decay\n---\n\n{}\n",
        row.event_id, row.ts_ns, iso, day, row.importance, row.text,
    )
}

/// `YYYY-MM-DD` (UTC) for the filename + frontmatter `day`.
fn day_string(ts_ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ts_ns / 1_000_000_000;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".into())
}

/// Full ISO-8601 UTC instant for the frontmatter `ts`.
fn iso_string(ts_ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ts_ns / 1_000_000_000;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn row(event_id: i64, ts_ns: i64, text: &str, importance: f64) -> PreDecayRow {
        PreDecayRow {
            event_id,
            ts_ns,
            text: text.to_string(),
            importance,
        }
    }

    // 2021-01-01T00:00:00Z in ns.
    const TS_2021: i64 = 1_609_459_200 * 1_000_000_000;

    #[test]
    fn empty_rows_writes_nothing_and_returns_zero() {
        let vault = TempDir::new().unwrap();
        let n = write_pre_decay_drafts(vault.path(), &[]);
        assert_eq!(n, 0);
        // PreDecay dir not even created for an empty pass.
        assert!(!vault.path().join("PreDecay").exists());
    }

    #[test]
    fn writes_one_draft_with_stable_frontmatter_and_verbatim_body() {
        let vault = TempDir::new().unwrap();
        let n =
            write_pre_decay_drafts(vault.path(), &[row(42, TS_2021, "ephemeral thought", 0.07)]);
        assert_eq!(n, 1);
        let path = vault.path().join("PreDecay").join("2021-01-01-42.md");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("event_id: 42"));
        assert!(content.contains("importance: 0.07"));
        assert!(content.contains("source: neoth-pre-decay"));
        assert!(content.contains("day: 2021-01-01"));
        // Body is verbatim, after the frontmatter close.
        let (_, body) = content
            .split_once("---\n\n")
            .expect("frontmatter then body");
        assert_eq!(body.trim_end(), "ephemeral thought");
    }

    #[test]
    fn count_matches_files_written_for_multiple_rows() {
        let vault = TempDir::new().unwrap();
        let rows = vec![
            row(1, TS_2021, "a", 0.05),
            row(2, TS_2021, "b", 0.09),
            row(3, TS_2021 + 86_400_000_000_000, "c", 0.01),
        ];
        let n = write_pre_decay_drafts(vault.path(), &rows);
        assert_eq!(n, 3);
        let dir = vault.path().join("PreDecay");
        let count = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 3, "exactly one .md per row, no stray .tmp");
    }

    #[test]
    fn filename_uses_event_day_not_pass_day() {
        // event_id 7 on 2021-01-02 → 2021-01-02-7.md (the MEMORY's day,
        // so the draft sorts with the period it covers).
        let vault = TempDir::new().unwrap();
        let ts_jan2 = TS_2021 + 86_400_000_000_000;
        write_pre_decay_drafts(vault.path(), &[row(7, ts_jan2, "x", 0.02)]);
        assert!(
            vault
                .path()
                .join("PreDecay")
                .join("2021-01-02-7.md")
                .exists()
        );
    }

    #[test]
    fn no_tmp_files_left_behind() {
        let vault = TempDir::new().unwrap();
        write_pre_decay_drafts(vault.path(), &[row(9, TS_2021, "y", 0.03)]);
        let dir = vault.path().join("PreDecay");
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            assert!(
                !p.to_string_lossy().ends_with(".tmp"),
                "atomic write must leave no .tmp: {}",
                p.display()
            );
        }
    }

    #[test]
    fn creates_predecay_dir_when_absent() {
        let vault = TempDir::new().unwrap();
        assert!(!vault.path().join("PreDecay").exists());
        write_pre_decay_drafts(vault.path(), &[row(1, TS_2021, "z", 0.04)]);
        assert!(vault.path().join("PreDecay").is_dir());
    }

    #[test]
    fn rewriting_same_event_overwrites_not_duplicates() {
        // A later pass re-drafting the same event_id (e.g. importance
        // nudged but still below floor) overwrites the prior draft rather
        // than erroring or duplicating — rename-over is idempotent.
        let vault = TempDir::new().unwrap();
        write_pre_decay_drafts(vault.path(), &[row(5, TS_2021, "first", 0.06)]);
        let n = write_pre_decay_drafts(vault.path(), &[row(5, TS_2021, "second", 0.02)]);
        assert_eq!(n, 1);
        let path = vault.path().join("PreDecay").join("2021-01-01-5.md");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("second"));
        assert!(!content.contains("first"));
    }

    #[test]
    fn extreme_timestamp_does_not_panic_and_still_drafts() {
        // The real invariant: an absurd `ts_ns` (here `i64::MIN`, the
        // clock-fault shape) must never panic the date formatter, and the
        // draft must still land (with whatever in-range or epoch-fallback
        // day the formatter yields). We assert the draft was written + a
        // single .md exists for the event — not a specific date string,
        // since `i64::MIN / 1e9s` is actually an in-range (~1678) date.
        let vault = TempDir::new().unwrap();
        let n = write_pre_decay_drafts(vault.path(), &[row(11, i64::MIN, "w", 0.01)]);
        assert_eq!(n, 1, "extreme ts must not block the draft");
        let files: Vec<String> = std::fs::read_dir(vault.path().join("PreDecay"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files.len(), 1);
        assert!(
            files[0].ends_with("-11.md"),
            "draft carries the event_id, got {files:?}"
        );
    }
}
