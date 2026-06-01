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
        // Trim braces if a UUID was stringified with them (rare but cheap).
        let id = self.session_id.trim_matches(|c| c == '{' || c == '}');
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

        let header_if_new = if path.exists() {
            String::new()
        } else {
            format!(
                "---\nsession: {}\nopened: {}\n---\n\n# Session {}\n\n",
                self.session_id,
                self.opened_at.format("%Y-%m-%d %H:%M:%S UTC"),
                self.session_id,
            )
        };

        let block = format!(
            "{}## {}\n\n**You:**\n\n{}\n\n**Neoth:**\n\n{}\n\n",
            header_if_new,
            ts.format("%Y-%m-%d %H:%M:%S UTC"),
            operator_msg.trim_end(),
            neoth_reply.trim_end(),
        );

        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("open archive file {}", path.display()))?;
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
}
