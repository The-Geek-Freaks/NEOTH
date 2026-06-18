//! Session archive — Phase 28a R-22 MT-4.
//!
//! Every turn (operator input + NEOTH response) is appended to a markdown
//! file per session. The archive is human-readable, Obsidian-Periodic-Notes
//! compatible, and **separate from the SQLite views** — operators can browse,
//! share, or import these files without touching the daemon indexes.
//!
//! Path scheme:
//!
//! ```text
//! ~/.neoth/archive/sessions/2026-05-14/093412-<session-uuid>.md
//! ```
//!
//! ## Invariants
//!
//! - **Append-only.** Once a turn is written it is never edited or deleted.
//! - **Per-turn flush.** A session aborted mid-turn loses only the turn in
//!   flight, not the prior history.
//! - **No daemon dependency.** The writer takes a path + session id and
//!   nothing else. It does not touch SQLite, does not require the WAL writer.
//! - **Hebbian-DECAY immune.** The R-24 decay pass operates on views, not
//!   on these files. This is the operator's right-to-keep what NEOTH wants
//!   to forget.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Process-wide serialization of archive appends.
///
/// COR-29: appends used a `path.exists()` check followed by a *separate*
/// `OpenOptions::create(true)` open — a TOCTOU window where two concurrent
/// first-writers could each see "no file", both emit the YAML frontmatter, and
/// duplicate it (or interleave a turn into the middle of another writer's
/// block). Archive writes are tiny and infrequent (one per chat turn), so a
/// single global async mutex held across the create-or-append + write + fsync
/// makes the whole sequence atomic. Combined with `create_new(true)` below the
/// first writer is unambiguous and its frontmatter+block lands before any
/// other turn — frontmatter exactly once, at the top, no lost turns.
static ARCHIVE_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Sanitize a session id to the safe filesystem character set `[A-Za-z0-9_-]`.
///
/// COR-29: the session id flows straight into the archive filename. Without
/// this a crafted id such as `../../../etc/cron.d/neoth` would escape the
/// archive root (path traversal). Every character outside the allowlist becomes
/// `_`; a fully stripped id falls back to `_` so the filename stem is never
/// empty. Deterministic, so the same id always maps to the same file.
fn sanitize_session_id(raw: &str) -> String {
    // Strip optional UUID braces first (legacy: some callers stringify with them).
    let trimmed = raw.trim_matches(|c| c == '{' || c == '}');
    let cleaned: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

/// Default archive root under `~/.neoth/archive/`.
pub fn default_archive_root() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth").join("archive")
}

/// One session's append handle. Cheap to construct; resolves the on-disk
/// path lazily on the first `append_turn` call so a session that never
/// produces a turn leaves no file behind.
#[derive(Clone, Debug)]
pub struct SessionArchive {
    root: PathBuf,
    session_id: String,
    /// Wall-clock time the session was opened. Determines the day-bucket
    /// and the `HHMMSS-` filename prefix so the archive groups sessions
    /// per local-time day rather than per UTC midnight.
    opened_at: DateTime<Utc>,
}

impl SessionArchive {
    /// New archive under `root` for `session_id`. `opened_at` should be the
    /// wall-clock time the session started — usually `Utc::now()` at the
    /// channel-handler / chat-CLI entry point.
    pub fn new<S: Into<String>>(root: PathBuf, session_id: S, opened_at: DateTime<Utc>) -> Self {
        Self {
            root,
            session_id: session_id.into(),
            opened_at,
        }
    }

    /// Path the archive will write to. Does not create parent dirs.
    pub fn file_path(&self) -> PathBuf {
        let day = self.opened_at.format("%Y-%m-%d").to_string();
        let time = self.opened_at.format("%H%M%S").to_string();
        // Sanitize to [A-Za-z0-9_-] so a crafted session id cannot escape the
        // archive root via path traversal (COR-29).
        let id = sanitize_session_id(&self.session_id);
        let stem = format!("{time}-{id}.md");
        self.root.join("sessions").join(day).join(stem)
    }

    /// Append one operator/NEOTH turn pair. Creates the file + parents on
    /// the first call. Subsequent calls open in append mode.
    ///
    /// `ts` is the per-turn timestamp (channel ingress time for inbound or
    /// provider response time for outbound). Lets the reader see exact
    /// timing rather than estimate from line order.
    pub async fn append_turn(
        &self,
        operator_msg: &str,
        neoth_reply: &str,
        ts: DateTime<Utc>,
    ) -> Result<()> {
        let path = self.file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create archive dir {}", parent.display()))?;
        }

        // Serialize the create-or-append decision + write + fsync so concurrent
        // first-writers can't duplicate the frontmatter or interleave turns
        // (COR-29). The guard spans the whole sequence; archive writes are tiny.
        let _write_guard = ARCHIVE_WRITE_LOCK.lock().await;

        // `create_new(true)` atomically claims first-writer status (O_EXCL):
        // exactly one open succeeds when the file is absent, closing the TOCTOU
        // window the old `path.exists()` + `create(true)` pair left open. Both
        // handles are append-mode so every write goes to EOF (no overwrite of a
        // concurrent writer's bytes, no mid-file frontmatter).
        let (mut f, is_new) = match fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(file) => (file, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .await
                    .with_context(|| format!("open archive file {}", path.display()))?;
                (file, false)
            }
            Err(e) => {
                return Err(e).with_context(|| format!("create archive file {}", path.display()));
            }
        };

        let header_if_new = if is_new {
            // GR-121 / COR-29 — sanitize the session id for the FILE CONTENT too,
            // not just the filename (file_path). A crafted id with newlines or
            // YAML-special characters would otherwise break out of the
            // `session:` frontmatter value or inject markdown into the heading.
            // Same `[A-Za-z0-9_-]` form as the filename keeps the two consistent.
            let id = sanitize_session_id(&self.session_id);
            format!(
                "---\nsession: {}\nopened: {}\n---\n\n# Session {}\n\n",
                id,
                self.opened_at.format("%Y-%m-%d %H:%M:%S UTC"),
                id,
            )
        } else {
            String::new()
        };

        let block = format!(
            "{}## {}\n\n**You:**\n\n{}\n\n**Neoth:**\n\n{}\n\n",
            header_if_new,
            ts.format("%Y-%m-%d %H:%M:%S UTC"),
            operator_msg.trim_end(),
            neoth_reply.trim_end(),
        );

        f.write_all(block.as_bytes())
            .await
            .with_context(|| format!("write turn to {}", path.display()))?;
        f.sync_data()
            .await
            .with_context(|| format!("fsync archive {}", path.display()))?;
        Ok(())
    }
}

/// Sweep helper used by `neoth memory --archive` (Phase 28a MT-5) and by the
/// Obsidian R-5 vault sync (Phase 13). Lists archive files for one day.
pub async fn list_for_day(root: &Path, day: &str) -> Result<Vec<PathBuf>> {
    let day_dir = root.join("sessions").join(day);
    if !day_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut rd = fs::read_dir(&day_dir)
        .await
        .with_context(|| format!("read archive dir {}", day_dir.display()))?;
    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("md") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    #[tokio::test]
    async fn appends_first_turn_creates_file_with_frontmatter() {
        let dir = tempdir().unwrap();
        let opened = Utc.with_ymd_and_hms(2026, 5, 14, 9, 34, 12).unwrap();
        let sa = SessionArchive::new(dir.path().to_path_buf(), "abc-123", opened);

        sa.append_turn("Hi Neoth.", "Hi operator.", opened)
            .await
            .expect("append");

        let path = sa.file_path();
        assert!(
            path.exists(),
            "archive file must exist at {}",
            path.display()
        );
        let body = fs::read_to_string(&path).await.unwrap();
        assert!(body.starts_with("---\nsession: abc-123\n"));
        assert!(body.contains("**You:**\n\nHi Neoth."));
        assert!(body.contains("**Neoth:**\n\nHi operator."));
    }

    #[tokio::test]
    async fn frontmatter_and_heading_sanitize_a_crafted_session_id_gr121() {
        // GR-121 — a session id with newlines / YAML-special chars must NOT
        // inject into the frontmatter value or the markdown heading; both now
        // use the same `[A-Za-z0-9_-]` sanitization as the filename.
        let dir = tempdir().unwrap();
        let opened = Utc.with_ymd_and_hms(2026, 5, 14, 9, 34, 12).unwrap();
        let evil = "ok\ninjected: true\n# pwned";
        let sa = SessionArchive::new(dir.path().to_path_buf(), evil, opened);
        sa.append_turn("hi", "yo", opened).await.unwrap();

        let body = fs::read_to_string(&sa.file_path()).await.unwrap();
        assert!(
            !body.contains("injected: true"),
            "YAML injection must not survive: {body}"
        );
        assert!(
            !body.contains("# pwned"),
            "heading injection must not survive: {body}"
        );
        let id = sanitize_session_id(evil);
        assert!(
            body.contains(&format!("session: {id}\n")),
            "sanitized id in frontmatter: {body}"
        );
        assert!(
            body.contains(&format!("# Session {id}\n")),
            "sanitized id in heading: {body}"
        );
    }

    #[tokio::test]
    async fn appends_second_turn_skips_frontmatter() {
        let dir = tempdir().unwrap();
        let opened = Utc.with_ymd_and_hms(2026, 5, 14, 9, 34, 12).unwrap();
        let sa = SessionArchive::new(dir.path().to_path_buf(), "xyz", opened);

        sa.append_turn("one", "1", opened).await.unwrap();
        sa.append_turn("two", "2", opened).await.unwrap();

        let body = fs::read_to_string(sa.file_path()).await.unwrap();
        let count_frontmatter = body.matches("---\nsession:").count();
        assert_eq!(count_frontmatter, 1, "frontmatter should be written once");
        assert!(body.contains("one") && body.contains("two"));
    }

    #[tokio::test]
    async fn file_path_groups_by_day() {
        let dir = tempdir().unwrap();
        let opened = Utc.with_ymd_and_hms(2026, 5, 14, 9, 34, 12).unwrap();
        let sa = SessionArchive::new(dir.path().to_path_buf(), "s", opened);

        let p = sa.file_path();
        assert!(p.to_string_lossy().contains("sessions"));
        assert!(p.to_string_lossy().contains("2026-05-14"));
        assert!(
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("093412-")
        );
        assert!(p.extension().and_then(|s| s.to_str()) == Some("md"));
    }

    #[tokio::test]
    async fn list_for_day_returns_md_files_sorted() {
        let dir = tempdir().unwrap();
        let opened_a = Utc.with_ymd_and_hms(2026, 5, 14, 9, 0, 0).unwrap();
        let opened_b = Utc.with_ymd_and_hms(2026, 5, 14, 10, 0, 0).unwrap();
        SessionArchive::new(dir.path().to_path_buf(), "a", opened_a)
            .append_turn("hi", "hi", opened_a)
            .await
            .unwrap();
        SessionArchive::new(dir.path().to_path_buf(), "b", opened_b)
            .append_turn("hi", "hi", opened_b)
            .await
            .unwrap();

        let files = list_for_day(dir.path(), "2026-05-14").await.unwrap();
        assert_eq!(files.len(), 2);
        // Sort is alphabetical; "090000-a.md" < "100000-b.md".
        assert!(files[0].to_string_lossy().contains("090000-a.md"));
        assert!(files[1].to_string_lossy().contains("100000-b.md"));
    }

    #[test]
    fn sanitize_session_id_strips_traversal_and_keeps_safe_chars() {
        // COR-29: traversal + odd chars collapse to `_`; the result can never
        // contain a path separator or `.`, so it cannot escape the archive root.
        let s = sanitize_session_id("../../../etc/cron");
        assert!(!s.contains('/'), "no path separator: {s}");
        assert!(!s.contains('.'), "no dot (blocks ..): {s}");
        assert!(s.ends_with("etc_cron"), "got: {s}");
        // Safe ids (incl. brace-wrapped UUIDs) pass through unchanged.
        assert_eq!(sanitize_session_id("{abc-123_XY}"), "abc-123_XY");
        assert_eq!(sanitize_session_id("a b.c:d"), "a_b_c_d");
        // Empty input falls back to a single `_`; non-empty all-illegal input
        // maps char-for-char to `_` (still a valid, non-traversal stem).
        assert_eq!(sanitize_session_id(""), "_");
        assert_eq!(sanitize_session_id("///"), "___");
    }

    #[tokio::test]
    async fn concurrent_archive_writes_do_not_race() {
        // COR-29: many concurrent first-writers on the same archive must emit
        // the frontmatter exactly once, keep it at the top, and lose no turn.
        // The old exists()+create TOCTOU could duplicate the frontmatter.
        let dir = tempdir().unwrap();
        let opened = Utc.with_ymd_and_hms(2026, 5, 14, 9, 34, 12).unwrap();
        let sa = SessionArchive::new(dir.path().to_path_buf(), "race-test", opened);

        let mut handles = Vec::new();
        for i in 0..8u32 {
            let sa = sa.clone();
            handles.push(tokio::spawn(async move {
                sa.append_turn(&format!("op-{i}"), &format!("reply-{i}"), opened)
                    .await
                    .expect("concurrent append must succeed");
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let body = fs::read_to_string(sa.file_path()).await.unwrap();
        assert_eq!(
            body.matches("---\nsession: race-test").count(),
            1,
            "frontmatter must appear exactly once:\n{body}"
        );
        assert!(
            body.starts_with("---\nsession: race-test"),
            "frontmatter must be at the top:\n{body}"
        );
        for i in 0..8u32 {
            assert!(body.contains(&format!("op-{i}")), "missing turn op-{i}");
            assert!(body.contains(&format!("reply-{i}")), "missing reply-{i}");
        }
    }
}
