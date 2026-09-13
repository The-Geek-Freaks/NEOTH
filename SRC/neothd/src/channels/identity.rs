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
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::channels::registry::{ChannelId, ChannelRef};

/// One channel-native alias mapped to a human.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Alias {
    pub channel: String,
    /// None denotes preserved account-unbound v1 history.
    pub account_id: Option<String>,
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
    crate::time::now_unix_i64()
}

/// Opaque capability minted only after the existing singleton Telegram
/// admission has authenticated its configured numeric allowlist sender.
pub(crate) struct LegacySingletonAliasClaimAuthority {
    expected_sender_id: String,
    expected_channel_ref: ChannelRef,
}

impl LegacySingletonAliasClaimAuthority {
    /// Only a startup-owned admission proof can mint production claim authority.
    pub(crate) fn from_admitted_telegram_singleton(
        admission: &crate::cli::serve_tasks::AdmittedLegacyTelegramSingleton,
    ) -> Self {
        Self {
            expected_sender_id: admission.sender_id().to_string(),
            expected_channel_ref: ChannelRef::default_account(ChannelId::Telegram),
        }
    }

    #[cfg(test)]
    fn for_admitted_telegram_singleton(sender_id: u64) -> Self {
        Self::from_admitted_telegram_singleton(
            &crate::cli::serve_tasks::AdmittedLegacyTelegramSingleton::for_test(sender_id),
        )
    }

    fn permits(&self, channel_ref: &ChannelRef, sender_id: &str) -> bool {
        self.expected_channel_ref == *channel_ref && self.expected_sender_id == sender_id
    }
}

pub(crate) struct ResolveInboundIdentity<'a> {
    pub channel_ref: &'a ChannelRef,
    pub sender_id: &'a str,
    pub chat_id: &'a str,
    pub pinned_operator_uuid: Option<&'a str>,
    pub legacy_singleton_claim: Option<&'a LegacySingletonAliasClaimAuthority>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacySingletonAliasClaim {
    pub channel_ref: ChannelRef,
    pub sender_id: String,
    pub chat_id: String,
    pub uuid: String,
    pub claimed_at_unix: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ResolvedInboundIdentity {
    pub human_uuid: String,
    pub legacy_claim: Option<LegacySingletonAliasClaim>,
}

/// Strict v2 reader: it never reads the account-unbound v1 alias table.
pub(crate) fn lookup_human_uuid_v2(
    conn: &Connection,
    channel_ref: &ChannelRef,
    sender_id: &str,
    chat_id: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT uuid FROM idx_human_identity_aliases_v2
         WHERE channel=?1 AND account_id=?2 AND sender_id=?3 AND chat_id=?4",
        rusqlite::params![
            channel_ref.channel_id.as_str(),
            channel_ref.account_id.as_str(),
            sender_id,
            chat_id
        ],
        |row| row.get(0),
    )
    .optional()
    .context("lookup account-qualified identity alias")
}

/// Writer-only resolution. Its single IMMEDIATE transaction rechecks v2 and
/// either creates a new v2 person or atomically records the one permitted v1
/// bridge with its claim receipt. It never updates v1 aliases.
pub(crate) fn resolve_or_create_human_uuid_v2(
    conn: &Connection,
    request: ResolveInboundIdentity<'_>,
) -> Result<ResolvedInboundIdentity> {
    if let Some(uuid) = lookup_human_uuid_v2(
        conn,
        request.channel_ref,
        request.sender_id,
        request.chat_id,
    )? {
        return Ok(ResolvedInboundIdentity {
            human_uuid: uuid,
            legacy_claim: None,
        });
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .context("begin account-qualified identity resolution")?;
    if let Some(uuid) =
        lookup_human_uuid_v2(&tx, request.channel_ref, request.sender_id, request.chat_id)?
    {
        tx.commit()?;
        return Ok(ResolvedInboundIdentity {
            human_uuid: uuid,
            legacy_claim: None,
        });
    }
    let legacy_uuid = match (
        request.legacy_singleton_claim,
        request.pinned_operator_uuid.filter(|uuid| !uuid.is_empty()),
    ) {
        (Some(authority), Some(pin))
            if authority.permits(request.channel_ref, request.sender_id) =>
        {
            tx.query_row(
                "SELECT uuid FROM idx_human_identity_aliases
                     WHERE channel=?1 AND sender_id=?2 AND chat_id=?3 AND uuid=?4",
                rusqlite::params![
                    request.channel_ref.channel_id.as_str(),
                    request.sender_id,
                    request.chat_id,
                    pin
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        }
        _ => None,
    };
    let claimed_at_unix = now_unix();
    let (human_uuid, legacy_claim) = if let Some(uuid) = legacy_uuid {
        tx.execute(
            "INSERT INTO idx_human_identity_aliases_v2
             (uuid, channel, account_id, sender_id, chat_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                uuid,
                request.channel_ref.channel_id.as_str(),
                request.channel_ref.account_id.as_str(),
                request.sender_id,
                request.chat_id
            ],
        )?;
        tx.execute(
            "INSERT INTO idx_human_identity_legacy_claims
             (channel, account_id, sender_id, chat_id, uuid, claimed_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                request.channel_ref.channel_id.as_str(),
                request.channel_ref.account_id.as_str(),
                request.sender_id,
                request.chat_id,
                uuid,
                claimed_at_unix
            ],
        )?;
        (
            uuid.clone(),
            Some(LegacySingletonAliasClaim {
                channel_ref: request.channel_ref.clone(),
                sender_id: request.sender_id.to_owned(),
                chat_id: request.chat_id.to_owned(),
                uuid,
                claimed_at_unix,
            }),
        )
    } else {
        let uuid = uuid::Uuid::now_v7().to_string();
        tx.execute(
            "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES (?1, ?2)",
            rusqlite::params![uuid, claimed_at_unix],
        )?;
        tx.execute(
            "INSERT INTO idx_human_identity_aliases_v2
             (uuid, channel, account_id, sender_id, chat_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                uuid,
                request.channel_ref.channel_id.as_str(),
                request.channel_ref.account_id.as_str(),
                request.sender_id,
                request.chat_id
            ],
        )?;
        (uuid, None)
    };
    tx.commit()?;
    Ok(ResolvedInboundIdentity {
        human_uuid,
        legacy_claim,
    })
}

/// Read-only lookup of an existing `human_uuid` for a `(channel, sender_id,
/// chat_id)` triple. Returns `None` on first sight (no alias row yet). This is a
/// PURE SELECT — safe to run on the `ViewsExecutor` reader pool (TRAIL-04). The
/// create path lives in [`resolve_or_create_human_uuid`], which INSERTs and so
/// MUST run on the single writer connection, never a reader.
pub fn lookup_human_uuid(
    conn: &Connection,
    channel: &str,
    sender_id: &str,
    chat_id: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT uuid FROM idx_human_identity_aliases \
         WHERE channel = ?1 AND sender_id = ?2 AND chat_id = ?3",
        rusqlite::params![channel, sender_id, chat_id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .context("lookup identity alias")
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
    if let Some(uuid) = lookup_human_uuid(conn, channel, sender_id, chat_id)? {
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
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .context("begin atomic identity merge")?;
    let canonical_exists = tx
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
        let mut stmt = tx.prepare(
            "SELECT channel, NULL AS account_id, sender_id, chat_id FROM idx_human_identity_aliases WHERE uuid = ?1 \
             UNION ALL SELECT channel, account_id, sender_id, chat_id FROM idx_human_identity_aliases_v2 WHERE uuid = ?1 \
             ORDER BY channel, account_id, sender_id",
        )?;
        stmt.query_map([victim], |r| {
            Ok(Alias {
                channel: r.get(0)?,
                account_id: r.get(1)?,
                sender_id: r.get(2)?,
                chat_id: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "UPDATE OR IGNORE idx_human_identity_aliases SET uuid = ?1 WHERE uuid = ?2",
        rusqlite::params![canonical, victim],
    )
    .context("reassign aliases")?;
    // Any alias left on the victim collided with an existing canonical alias —
    // drop the duplicate (the canonical row already covers that triple).
    tx.execute(
        "DELETE FROM idx_human_identity_aliases WHERE uuid = ?1",
        [victim],
    )
    .context("drop leftover victim aliases")?;
    tx.execute(
        "UPDATE OR IGNORE idx_human_identity_aliases_v2 SET uuid = ?1 WHERE uuid = ?2",
        rusqlite::params![canonical, victim],
    )
    .context("reassign v2 aliases")?;
    tx.execute(
        "DELETE FROM idx_human_identity_aliases_v2 WHERE uuid = ?1",
        [victim],
    )
    .context("drop colliding v2 victim aliases")?;
    // Claims are immutable historical proof that the exact v1 UUID matched the
    // configured pin at claim time. A later identity merge must not rewrite it.
    // Tombstone (NOT delete) — keeps the merge reversible + the row out of `list`.
    tx.execute(
        "UPDATE idx_human_identity SET merged_into = ?1 WHERE uuid = ?2",
        rusqlite::params![canonical, victim],
    )
    .context("tombstone victim identity")?;
    tx.commit().context("commit atomic identity merge")?;
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
            "SELECT channel, NULL AS account_id, sender_id, chat_id
             FROM idx_human_identity_aliases WHERE uuid = ?1
             UNION ALL
             SELECT channel, account_id, sender_id, chat_id
             FROM idx_human_identity_aliases_v2 WHERE uuid = ?1
             ORDER BY channel, account_id, sender_id, chat_id",
        )?;
        let aliases: Vec<Alias> = astmt
            .query_map([&uuid], |r| {
                Ok(Alias {
                    channel: r.get(0)?,
                    account_id: r.get(1)?,
                    sender_id: r.get(2)?,
                    chat_id: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        if let Some(cf) = channel_filter
            && !aliases.iter().any(|a| a.channel == cf)
        {
            continue;
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
                sender_id TEXT NOT NULL, chat_id TEXT NOT NULL, UNIQUE(channel, sender_id, chat_id));
             CREATE TABLE idx_human_identity_aliases_v2 (uuid TEXT NOT NULL, channel TEXT NOT NULL,
                account_id TEXT NOT NULL, sender_id TEXT NOT NULL, chat_id TEXT NOT NULL,
                UNIQUE(channel, account_id, sender_id, chat_id));
             CREATE TABLE idx_human_identity_legacy_claims (channel TEXT NOT NULL, account_id TEXT NOT NULL,
                sender_id TEXT NOT NULL, chat_id TEXT NOT NULL, uuid TEXT NOT NULL, claimed_at_unix INTEGER NOT NULL,
                UNIQUE(channel, account_id, sender_id, chat_id));",
        )
        .unwrap();
        conn
    }

    fn telegram(account_id: &str) -> ChannelRef {
        ChannelRef::new(
            ChannelId::Telegram,
            crate::channels::registry::ChannelAccountId::new(account_id).unwrap(),
        )
    }

    fn resolve_v2<'a>(
        conn: &Connection,
        channel_ref: &'a ChannelRef,
        sender_id: &'a str,
        chat_id: &'a str,
        pinned_operator_uuid: Option<&'a str>,
        legacy_singleton_claim: Option<&'a LegacySingletonAliasClaimAuthority>,
    ) -> ResolvedInboundIdentity {
        resolve_or_create_human_uuid_v2(
            conn,
            ResolveInboundIdentity {
                channel_ref,
                sender_id,
                chat_id,
                pinned_operator_uuid,
                legacy_singleton_claim,
            },
        )
        .unwrap()
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
        assert_eq!(
            before.len(),
            1,
            "the slack alias reassigned to the telegram uuid"
        );
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
        assert_eq!(
            resolved, tg,
            "the merged slack alias now points at the canonical"
        );
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

    #[test]
    fn v2_same_key_is_stable_and_accounts_are_isolated() {
        let conn = db();
        let default = telegram("default");
        let account_b = telegram("account-b");
        let first = resolve_v2(&conn, &default, "100", "chat", None, None);
        let again = resolve_v2(&conn, &default, "100", "chat", None, None);
        let other_account = resolve_v2(&conn, &account_b, "100", "chat", None, None);
        assert_eq!(first.human_uuid, again.human_uuid);
        assert_ne!(first.human_uuid, other_account.human_uuid);
        assert!(first.legacy_claim.is_none());
    }

    #[test]
    fn ordinary_v2_resolution_never_reads_or_mutates_v1() {
        let conn = db();
        conn.execute(
            "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES ('legacy', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_human_identity_aliases (uuid, channel, sender_id, chat_id) VALUES ('legacy', 'telegram', '100', 'chat')",
            [],
        )
        .unwrap();
        let before: (String, String, String, String) = conn
            .query_row(
                "SELECT uuid, channel, sender_id, chat_id FROM idx_human_identity_aliases",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let channel_ref = telegram("default");
        let resolved = resolve_v2(&conn, &channel_ref, "100", "chat", None, None);
        assert_ne!(resolved.human_uuid, "legacy");
        let after: (String, String, String, String) = conn
            .query_row(
                "SELECT uuid, channel, sender_id, chat_id FROM idx_human_identity_aliases",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn exact_admitted_default_telegram_alias_claims_v1_atomically() {
        let conn = db();
        conn.execute(
            "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES ('pin', 1)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO idx_human_identity_aliases (uuid, channel, sender_id, chat_id) VALUES ('pin', 'telegram', '100', 'chat')", []).unwrap();
        let authority = LegacySingletonAliasClaimAuthority::for_admitted_telegram_singleton(100);
        let channel_ref = telegram("default");
        let resolved = resolve_v2(
            &conn,
            &channel_ref,
            "100",
            "chat",
            Some("pin"),
            Some(&authority),
        );
        assert_eq!(resolved.human_uuid, "pin");
        assert!(resolved.legacy_claim.is_some());
        assert_eq!(
            lookup_human_uuid_v2(&conn, &channel_ref, "100", "chat")
                .unwrap()
                .as_deref(),
            Some("pin")
        );
        let claims: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_human_identity_legacy_claims WHERE uuid='pin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(claims, 1);
    }

    #[test]
    fn legacy_claim_requires_each_exact_condition() {
        let cases: Vec<(Option<u64>, Option<&str>, ChannelRef, &str)> = vec![
            (None, Some("pin"), telegram("default"), "100"),
            (Some(100), None, telegram("default"), "100"),
            (Some(100), Some("wrong-pin"), telegram("default"), "100"),
            (Some(999), Some("pin"), telegram("default"), "100"),
            (Some(100), Some("pin"), telegram("account-b"), "100"),
            (Some(100), Some("pin"), telegram("default"), "999"),
        ];
        for (authority_sender, pin, channel_ref, sender) in cases {
            let conn = db();
            conn.execute(
                "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES ('pin', 1)",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO idx_human_identity_aliases (uuid, channel, sender_id, chat_id) VALUES ('pin', 'telegram', '100', 'chat')", []).unwrap();
            let authority = authority_sender
                .map(LegacySingletonAliasClaimAuthority::for_admitted_telegram_singleton);
            let resolved = resolve_v2(&conn, &channel_ref, sender, "chat", pin, authority.as_ref());
            assert_ne!(resolved.human_uuid, "pin");
            assert!(resolved.legacy_claim.is_none());
            let claims: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM idx_human_identity_legacy_claims",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(claims, 0);
        }
    }

    #[test]
    fn failed_claim_write_rolls_back_v2_alias() {
        let conn = db();
        conn.execute(
            "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES ('pin', 1)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO idx_human_identity_aliases (uuid, channel, sender_id, chat_id) VALUES ('pin', 'telegram', '100', 'chat')", []).unwrap();
        conn.execute("INSERT INTO idx_human_identity_legacy_claims (channel, account_id, sender_id, chat_id, uuid, claimed_at_unix) VALUES ('telegram', 'default', '100', 'chat', 'prior', 1)", []).unwrap();
        let authority = LegacySingletonAliasClaimAuthority::for_admitted_telegram_singleton(100);
        let channel_ref = telegram("default");
        let result = resolve_or_create_human_uuid_v2(
            &conn,
            ResolveInboundIdentity {
                channel_ref: &channel_ref,
                sender_id: "100",
                chat_id: "chat",
                pinned_operator_uuid: Some("pin"),
                legacy_singleton_claim: Some(&authority),
            },
        );
        assert!(result.is_err());
        let aliases: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_human_identity_aliases_v2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            aliases, 0,
            "failed claim receipt must roll back its v2 alias"
        );
    }

    #[test]
    fn merge_and_list_include_v1_and_v2_without_leaving_v2_victim_rows() {
        let conn = db();
        let canonical = resolve_or_create_human_uuid(&conn, "slack", "canonical", "chat").unwrap();
        let channel_ref = telegram("default");
        let victim = resolve_v2(&conn, &channel_ref, "100", "chat", None, None).human_uuid;
        let before = merge_human_uuids(&conn, &canonical, &victim).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].account_id.as_deref(), Some("default"));
        let v2_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_human_identity_aliases_v2 WHERE uuid=?1",
                [&victim],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v2_left, 0);
        let identities = list_identities(&conn, None).unwrap();
        assert_eq!(identities.len(), 1);
        assert!(
            identities[0]
                .aliases
                .iter()
                .any(|alias| alias.account_id.as_deref() == Some("default"))
        );
    }

    #[test]
    fn merge_preserves_claim_provenance_while_moving_claimed_v2_alias() {
        let conn = db();
        conn.execute(
            "INSERT INTO idx_human_identity (uuid, created_at_unix) VALUES ('pin', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_human_identity_aliases VALUES ('pin', 'telegram', '100', 'chat')",
            [],
        )
        .unwrap();
        let default = telegram("default");
        let authority = LegacySingletonAliasClaimAuthority::for_admitted_telegram_singleton(100);
        let claimed = resolve_v2(
            &conn,
            &default,
            "100",
            "chat",
            Some("pin"),
            Some(&authority),
        );
        let canonical = resolve_or_create_human_uuid(&conn, "slack", "canonical", "chat").unwrap();
        merge_human_uuids(&conn, &canonical, &claimed.human_uuid).unwrap();
        let claim: (String, i64) = conn
            .query_row(
                "SELECT uuid, claimed_at_unix FROM idx_human_identity_legacy_claims",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(claim.0, "pin");
        assert!(claim.1 > 0);
        assert_eq!(
            lookup_human_uuid_v2(&conn, &default, "100", "chat")
                .unwrap()
                .as_deref(),
            Some(canonical.as_str())
        );
    }

    #[test]
    fn merge_failure_rolls_back_v1_v2_and_tombstone_together() {
        let conn = db();
        let canonical = resolve_or_create_human_uuid(&conn, "slack", "canonical", "chat").unwrap();
        let victim = resolve_or_create_human_uuid(&conn, "telegram", "100", "chat").unwrap();
        let default = telegram("default");
        let v2_victim = resolve_v2(&conn, &default, "100", "other-chat", None, None).human_uuid;
        // Give the same victim one v2 alias so both table moves precede the
        // failing tombstone update.
        conn.execute(
            "UPDATE idx_human_identity_aliases_v2 SET uuid=?1 WHERE uuid=?2",
            [&victim, &v2_victim],
        )
        .unwrap();
        conn.execute_batch(&format!("CREATE TRIGGER abort_identity_tombstone BEFORE UPDATE OF merged_into ON idx_human_identity WHEN NEW.uuid='{victim}' BEGIN SELECT RAISE(ABORT, 'stop merge'); END;")).unwrap();
        assert!(merge_human_uuids(&conn, &canonical, &victim).is_err());
        let v1: String = conn
            .query_row(
                "SELECT uuid FROM idx_human_identity_aliases WHERE channel='telegram'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let v2: String = conn
            .query_row(
                "SELECT uuid FROM idx_human_identity_aliases_v2 WHERE chat_id='other-chat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let tombstone: Option<String> = conn
            .query_row(
                "SELECT merged_into FROM idx_human_identity WHERE uuid=?1",
                [&victim],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v1, victim);
        assert_eq!(v2, victim);
        assert_eq!(tombstone, None);
    }
}
