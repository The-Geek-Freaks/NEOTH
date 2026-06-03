//! EM-01b P1c — inbound-email dedup / seen-state.
//!
//! `neoth email fetch` reads `SEARCH UNSEEN` with `BODY.PEEK[]` (deliberately
//! non-destructive — it never flips the server's `\Seen` flag), so a message
//! the operator hasn't opened in their own client stays UNSEEN and would be
//! re-pulled + re-triaged on every fetch. This table records each message
//! NEOTH already triaged so a re-fetch skips it.
//!
//! Dedup key: the stable RFC822 `Message-ID` when present (survives IMAP
//! `UIDVALIDITY` resets / mailbox moves), falling back to the IMAP UID. Pure
//! repository fns over a `rusqlite::Connection` (the `idx_email_seen` table is
//! created in `memory::store::apply_schema`).

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

/// `true` if this dedup key was already recorded (already triaged).
pub fn is_seen(conn: &Connection, dedup_key: &str) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM idx_email_seen WHERE dedup_key = ?1",
            [dedup_key],
            |row| row.get(0),
        )
        .optional()
        .context("query idx_email_seen")?;
    Ok(found.is_some())
}

/// Record a message as seen. Idempotent (`INSERT OR IGNORE` on the PK) so a
/// re-mark of the same key is a no-op and never errors.
pub fn mark_seen(
    conn: &Connection,
    dedup_key: &str,
    imap_uid: Option<&str>,
    now_unix: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO idx_email_seen (dedup_key, imap_uid, first_seen_unix) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![dedup_key, imap_uid, now_unix],
    )
    .context("insert idx_email_seen")?;
    Ok(())
}

/// Total number of recorded seen messages — used by the CLI to report how many
/// of a fetch batch were skipped as duplicates.
pub fn seen_count(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM idx_email_seen", [], |row| row.get(0))
        .context("count idx_email_seen")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        // The real schema lives in store::apply_schema; for a hermetic unit
        // test we create just the one table this module touches.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_email_seen (
                dedup_key TEXT NOT NULL PRIMARY KEY,
                imap_uid TEXT,
                first_seen_unix INTEGER NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn unseen_then_seen_after_mark() {
        let conn = mem_db();
        assert!(!is_seen(&conn, "<msg-1@example.com>").unwrap());
        mark_seen(&conn, "<msg-1@example.com>", Some("42"), 1000).unwrap();
        assert!(is_seen(&conn, "<msg-1@example.com>").unwrap());
        // A different key is still unseen.
        assert!(!is_seen(&conn, "<msg-2@example.com>").unwrap());
    }

    #[test]
    fn mark_is_idempotent() {
        let conn = mem_db();
        mark_seen(&conn, "k", Some("1"), 1000).unwrap();
        // Re-marking the same key (even with a different uid/ts) must not error
        // and must not duplicate.
        mark_seen(&conn, "k", Some("2"), 2000).unwrap();
        assert_eq!(seen_count(&conn).unwrap(), 1);
    }

    #[test]
    fn null_uid_is_allowed() {
        let conn = mem_db();
        mark_seen(&conn, "k", None, 1000).unwrap();
        assert!(is_seen(&conn, "k").unwrap());
        assert_eq!(seen_count(&conn).unwrap(), 1);
    }
}
