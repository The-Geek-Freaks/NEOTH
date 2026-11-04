//! Account-, epoch- and purpose-bound completion in the existing views store.
//! An old unscoped row is ambiguous, never proof of this mailbox's completion
//! or permission to repeat an external effect. CLI re-triage cannot clear it.

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::email::inbound::InboundEmail;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Triage,
    Ingest,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::Ingest => "ingest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeenState {
    Unseen,
    Seen,
    LegacyAmbiguous,
    InputConflict,
}

/// Constructed from the same mailbox identity used by existing Paperless WAL
/// claims and vault notes. No credentials or raw message content are stored.
pub(crate) struct Identity {
    unit_sha256: String,
    legacy_key: String,
    input_sha256: String,
}

pub(crate) fn mail_key(email: &InboundEmail, uid_validity: u32) -> Result<String> {
    if let Some(message_id) = email
        .message_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return Ok(format!("message-id:{message_id}"));
    }
    ensure!(uid_validity > 0, "IMAP UID fallback requires UIDVALIDITY");
    ensure!(!email.uid.is_empty(), "IMAP UID fallback requires a UID");
    Ok(format!("uidvalidity:{uid_validity}:uid:{}", email.uid))
}

impl Identity {
    pub(crate) fn inbox(
        host: &str,
        port: u16,
        username: &str,
        email: &InboundEmail,
        uid_validity: u32,
    ) -> Result<Self> {
        ensure!(
            !host.trim_end_matches('.').is_empty() && port > 0 && !username.is_empty(),
            "email seen-state requires a complete mailbox identity"
        );
        let mail_key = mail_key(email, uid_validity)?;
        // UID/Message-ID are already bound by the immutable mailbox unit.
        // These exact immutable inputs drive triage and the downstream rendition.
        let input = serde_json::to_vec(&(
            "neoth.email-input.v1",
            &email.from,
            &email.from_domain,
            &email.subject,
            &email.body,
            &email.attachment_filenames,
            &email.auth_results,
        )).context("bind full email input")?;
        Ok(Self {
            unit_sha256: crate::wal::paperless_post_receipts::mail_unit_sha256(
                host, port, username, &mail_key,
            ),
            legacy_key: email.dedup_key().to_owned(),
            input_sha256: format!("{:x}", Sha256::digest(&input)),
        })
    }
}

pub(crate) fn state(conn: &Connection, identity: &Identity, purpose: Purpose) -> Result<SeenState> {
    let found: Option<Option<String>> = conn
        .query_row(
            "SELECT input_sha256 FROM idx_email_seen_scoped \
             WHERE unit_sha256 = ?1 AND purpose = ?2",
            rusqlite::params![identity.unit_sha256, purpose.as_str()],
            |row| row.get(0),
        )
        .optional()
        .context("query scoped email completion")?;
    if let Some(input) = found {
        return Ok(match (purpose, input) {
            (Purpose::Triage, _) => SeenState::Seen,
            (Purpose::Ingest, None) => SeenState::LegacyAmbiguous,
            (Purpose::Ingest, Some(input)) if input == identity.input_sha256 => SeenState::Seen,
            (Purpose::Ingest, Some(_)) => SeenState::InputConflict,
        });
    }
    if super::is_seen(conn, &identity.legacy_key)? {
        return Ok(SeenState::LegacyAmbiguous);
    }
    Ok(SeenState::Unseen)
}

/// The caller records only its completed stage. Re-triage is harmless to the
/// ingest ledger; legacy ambiguity can never be promoted to ingest completion.
pub(crate) fn mark(
    conn: &Connection,
    identity: &Identity,
    purpose: Purpose,
    now_unix: i64,
) -> Result<()> {
    if purpose == Purpose::Ingest {
        ensure!(
            matches!(state(conn, identity, purpose)?, SeenState::Unseen | SeenState::Seen),
            "legacy or changed email input requires explicit reconciliation"
        );
    }
    let input = (purpose == Purpose::Ingest).then_some(identity.input_sha256.as_str());
    conn.execute(
            "INSERT INTO idx_email_seen_scoped (unit_sha256, purpose, first_seen_unix, input_sha256) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT(unit_sha256, purpose) DO NOTHING",
            rusqlite::params![identity.unit_sha256, purpose.as_str(), now_unix, input],
        )
        .context("record scoped email completion")?;
    ensure!(
        state(conn, identity, purpose)? == SeenState::Seen,
        "scoped email completion was not recorded for this input"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
