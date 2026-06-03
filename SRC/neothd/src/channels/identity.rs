//! SPEC-11 — cross-channel human identity (C-12/C-13).
//!
//! The same operator appears on Telegram, Slack, WhatsApp, … under different
//! channel-native `sender_id`s. This module mints ONE stable `human_uuid`
//! (UUID v7, time-sortable) per person + maps every `(channel, sender_id,
//! chat_id)` alias to it, so the inbound handler can stamp
//! `InboundMessage.human_uuid` + the operator can unify split identities with
//! `neoth identity merge`.
//!
//! Storage: `idx_human_identity` (one row per person) +
//! `idx_human_identity_aliases` (the channel-triple → uuid map), created in
//! `memory::store::apply_schema` (backward-safe CREATE-IF-NOT-EXISTS).

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

/// One channel-native alias mapped to a human.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Alias {
    pub channel: String,
    pub sender_id: String,
    pub chat_id: String,
}

/// One resolved person + all their aliases.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    pub uuid: String,
    pub created_at_unix: i64,
    pub aliases: Vec<Alias>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolve the `human_uuid` for a channel-native `(channel, sender_id,
/// chat_id)` triple, minting a fresh UUID v7 + identity row on first sight.
/// Idempotent: the same triple always returns the same uuid (the alias table's
/// UNIQUE constraint is the anchor, so a concurrent first-sight race converges
/// on one winner).
pub fn resolve_or_create_human_uuid(
    conn: &Connection,
    channel: &str,
    sender_id: &str,
    chat_id: &str,
) -> Result<String> {
    if let Some(uuid) = conn
        .query_row(
            "SELECT uuid FROM idx_human_identity_aliases \
             WHERE channel = ?1 AND sender_id = ?2 AND chat_id = ?3",
            rusqlite::params![channel, sender_id, chat_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .context("lookup identity alias")?
    {
        return Ok(uuid);
    }
    let uuid = uuid::Uuid::now_v7().to_string();
    conn.execute(
        "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES (?1, ?2)",
        rusqlite::params![uuid, now_unix()],
    )
    .context("insert identity")?;
    // INSERT OR IGNORE: a concurrent insert of the same alias (UNIQUE) is a
    // no-op; we then re-read to return whichever uuid won the race.
    conn.execute(
        "INSERT OR IGNORE INTO idx_human_identity_aliases (uuid, channel, sender_id, chat_id) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![uuid, channel, sender_id, chat_id],
    )
    .context("insert identity alias")?;
    let winning: String = conn
        .query_row(
            "SELECT uuid FROM idx_human_identity_aliases \
             WHERE channel = ?1 AND sender_id = ?2 AND chat_id = ?3",
            rusqlite::params![channel, sender_id, chat_id],
            |r| r.get(0),
        )
        .context("re-read identity alias")?;
    // If our mint lost the race, drop the orphan identity row we created.
    if winning != uuid {
        let _ = conn.execute(
            "DELETE FROM idx_human_identity WHERE uuid = ?1 \
             AND NOT EXISTS (SELECT 1 FROM idx_human_identity_aliases WHERE uuid = ?1)",
            rusqlite::params![uuid],
        );
    }
    Ok(winning)
}

/// Merge `victim` into `canonical`: every alias pointing at `victim` is
/// reassigned to `canonical`, then `victim` is TOMBSTONED (its `merged_into` is
/// set — the row is kept, NOT deleted, so the merge is reversible + auditable).
/// Returns the victim's aliases as they were BEFORE the merge (the audit
/// before-state — the caller emits a `0x9B IDENTITY_MERGED` frame with these so
/// a future `neoth identity split` can reconstruct the split). An alias that
/// would collide with an existing canonical alias (UNIQUE) is dropped.
pub fn merge_human_uuids(conn: &Connection, canonical: &str, victim: &str) -> Result<Vec<Alias>> {
    if canonical == victim {
        anyhow::bail!("cannot merge an identity into itself");
    }
    let canonical_exists = conn
        .query_row(
            "SELECT 1 FROM idx_human_identity WHERE uuid = ?1",
            [canonical],
            |_| Ok(()),
        )
        .optional()
        .context("check canonical")?
        .is_some();
    if !canonical_exists {
        anyhow::bail!("canonical identity {canonical} does not exist");
    }
    // Capture the victim's aliases BEFORE reassignment — the reversible
    // before-state for the audit frame.
    let before: Vec<Alias> = {
        let mut stmt = conn.prepare(
            "SELECT channel, sender_id, chat_id FROM idx_human_identity_aliases \
             WHERE uuid = ?1 ORDER BY channel, sender_id",
        )?;
        stmt.query_map([victim], |r| {
            Ok(Alias {
                channel: r.get(0)?,
                sender_id: r.get(1)?,
                chat_id: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    conn.execute(
        "UPDATE OR IGNORE idx_human_identity_aliases SET uuid = ?1 WHERE uuid = ?2",
        rusqlite::params![canonical, victim],
    )
    .context("reassign aliases")?;
    // Any alias left on the victim collided with an existing canonical alias —
    // drop the duplicate (the canonical row already covers that triple).
    conn.execute(
        "DELETE FROM idx_human_identity_aliases WHERE uuid = ?1",
        [victim],
    )
    .context("drop leftover victim aliases")?;
    // Tombstone (NOT delete) — keeps the merge reversible + the row out of `list`.
    conn.execute(
        "UPDATE idx_human_identity SET merged_into = ?1 WHERE uuid = ?2",
        rusqlite::params![canonical, victim],
    )
    .context("tombstone victim identity")?;
    Ok(before)
}

/// List every identity + its aliases, optionally filtered to those that have at
/// least one alias on `channel_filter`. Sorted by first-seen time (UUID v7
/// order ≈ creation order).
pub fn list_identities(conn: &Connection, channel_filter: Option<&str>) -> Result<Vec<Identity>> {
    let mut stmt = conn.prepare(
        "SELECT uuid, created_at_unix FROM idx_human_identity \
         WHERE merged_into IS NULL ORDER BY created_at_unix ASC, uuid ASC",
    )?;
    let ids: Vec<(String, i64)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (uuid, created) in ids {
        let mut astmt = conn.prepare(
            "SELECT channel, sender_id, chat_id FROM idx_human_identity_aliases \
             WHERE uuid = ?1 ORDER BY channel, sender_id",
        )?;
        let aliases: Vec<Alias> = astmt
            .query_map([&uuid], |r| {
                Ok(Alias {
                    channel: r.get(0)?,
                    sender_id: r.get(1)?,
                    chat_id: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        if let Some(cf) = channel_filter {
            if !aliases.iter().any(|a| a.channel == cf) {
                continue;
            }
        }
        out.push(Identity {
            uuid,
            created_at_unix: created,
            aliases,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory db with just the identity tables (mirrors the
    /// `memory::store::apply_schema` DDL so the module tests in isolation).
    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_human_identity (uuid TEXT NOT NULL PRIMARY KEY, created_at_unix INTEGER NOT NULL, merged_into TEXT);
             CREATE TABLE idx_human_identity_aliases (uuid TEXT NOT NULL, channel TEXT NOT NULL, \
                sender_id TEXT NOT NULL, chat_id TEXT NOT NULL, UNIQUE(channel, sender_id, chat_id));",
        )
        .unwrap();
        conn
    }

    #[test]
    fn resolve_creates_then_returns_same_uuid() {
        let conn = db();
        let u1 = resolve_or_create_human_uuid(&conn, "telegram", "100", "chatA").unwrap();
        let u2 = resolve_or_create_human_uuid(&conn, "telegram", "100", "chatA").unwrap();
        assert_eq!(u1, u2, "same triple must resolve to the same uuid");
        // Exactly one identity + one alias row.
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_human_identity", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn resolve_different_triples_get_different_uuids() {
        let conn = db();
        let a = resolve_or_create_human_uuid(&conn, "telegram", "100", "chatA").unwrap();
        let b = resolve_or_create_human_uuid(&conn, "slack", "U200", "chatB").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn merge_reassigns_aliases_and_deletes_victim() {
        let conn = db();
        let tg = resolve_or_create_human_uuid(&conn, "telegram", "100", "chatA").unwrap();
        let sl = resolve_or_create_human_uuid(&conn, "slack", "U200", "chatB").unwrap();
        let before = merge_human_uuids(&conn, &tg, &sl).unwrap();
        assert_eq!(before.len(), 1, "the slack alias reassigned to the telegram uuid");
        assert_eq!(before[0].channel, "slack");
        // Victim is TOMBSTONED (kept, merged_into set), not deleted — reversible.
        let merged_into: Option<String> = conn
            .query_row(
                "SELECT merged_into FROM idx_human_identity WHERE uuid = ?1",
                [&sl],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(merged_into.as_deref(), Some(tg.as_str()));
        // `list` excludes the tombstoned victim → only the canonical remains.
        assert_eq!(list_identities(&conn, None).unwrap().len(), 1);
        let resolved = resolve_or_create_human_uuid(&conn, "slack", "U200", "chatB").unwrap();
        assert_eq!(resolved, tg, "the merged slack alias now points at the canonical");
    }

    #[test]
    fn merge_self_errors() {
        let conn = db();
        let u = resolve_or_create_human_uuid(&conn, "telegram", "1", "c").unwrap();
        assert!(merge_human_uuids(&conn, &u, &u).is_err());
    }

    #[test]
    fn merge_unknown_canonical_errors() {
        let conn = db();
        let v = resolve_or_create_human_uuid(&conn, "telegram", "1", "c").unwrap();
        assert!(merge_human_uuids(&conn, "no-such-uuid", &v).is_err());
    }

    #[test]
    fn list_filters_by_channel() {
        let conn = db();
        resolve_or_create_human_uuid(&conn, "telegram", "100", "chatA").unwrap();
        resolve_or_create_human_uuid(&conn, "slack", "U200", "chatB").unwrap();
        assert_eq!(list_identities(&conn, None).unwrap().len(), 2);
        let only_tg = list_identities(&conn, Some("telegram")).unwrap();
        assert_eq!(only_tg.len(), 1);
        assert_eq!(only_tg[0].aliases[0].channel, "telegram");
    }
}
