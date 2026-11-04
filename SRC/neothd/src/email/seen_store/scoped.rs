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
    ContextConflict,
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
        ))
        .context("bind full email input")?;
        Ok(Self {
            unit_sha256: crate::wal::paperless_post_receipts::mail_unit_sha256(
                host, port, username, &mail_key,
            ),
            legacy_key: email.dedup_key().to_owned(),
            input_sha256: format!("{:x}", Sha256::digest(&input)),
        })
    }
}

/// Non-secret target configuration only, not principal or approval evidence.
pub(crate) struct DeliveryContext {
    sha256: String,
}

impl DeliveryContext {
    pub(crate) fn new(
        vault: Option<&str>,
        subdir: &str,
        paperless_url: Option<&str>,
        token_present: bool,
        token_usable: bool,
    ) -> Result<Self> {
        ensure!(
            !token_usable || token_present,
            "usable token must be present"
        );
        let encoded = serde_json::to_vec(&(
            "neoth.email-delivery-context.v1",
            vault,
            vault.map(|_| subdir),
            paperless_url,
            token_present,
            token_usable,
        ))
        .context("bind email delivery targets")?;
        Ok(Self {
            sha256: format!("{:x}", Sha256::digest(&encoded)),
        })
    }
}

pub(crate) enum Completion<'a> {
    Triage,
    Delivery(&'a DeliveryContext),
    Quarantine,
}

struct ScopedRow {
    input_sha256: Option<String>,
    completion_kind: Option<String>,
    context_sha256: Option<String>,
}

fn read_scoped(
    conn: &Connection,
    identity: &Identity,
    purpose: Purpose,
) -> Result<Option<ScopedRow>> {
    conn.query_row(
        "SELECT input_sha256, completion_kind, context_sha256 FROM idx_email_seen_scoped \
         WHERE unit_sha256 = ?1 AND purpose = ?2",
        rusqlite::params![identity.unit_sha256, purpose.as_str()],
        |row| {
            Ok(ScopedRow {
                input_sha256: row.get(0)?,
                completion_kind: row.get(1)?,
                context_sha256: row.get(2)?,
            })
        },
    )
    .optional()
    .context("query scoped email completion")
}

pub(crate) fn state(
    conn: &Connection,
    identity: &Identity,
    purpose: Purpose,
    context: Option<&DeliveryContext>,
) -> Result<SeenState> {
    let Some(row) = read_scoped(conn, identity, purpose)? else {
        return Ok(if super::is_seen(conn, &identity.legacy_key)? {
            SeenState::LegacyAmbiguous
        } else {
            SeenState::Unseen
        });
    };
    if purpose == Purpose::Triage {
        return Ok(SeenState::Seen);
    }
    let Some(input) = row.input_sha256.as_deref() else {
        return Ok(SeenState::LegacyAmbiguous);
    };
    if input != identity.input_sha256 {
        return Ok(SeenState::InputConflict);
    }
    Ok(match row.completion_kind.as_deref() {
        Some("quarantine") if row.context_sha256.is_none() => SeenState::Seen,
        Some("delivery") => match row.context_sha256.as_deref() {
            None => SeenState::LegacyAmbiguous,
            Some(stored) => match context {
                Some(expected) if stored == expected.sha256 => SeenState::Seen,
                _ => SeenState::ContextConflict,
            },
        },
        _ => SeenState::LegacyAmbiguous,
    })
}

/// Completion is explicit: a quarantine cannot be adopted as delivery or vice
/// versa. A mismatched or historical row never authorizes a new external effect.
pub(crate) fn mark(
    conn: &Connection,
    identity: &Identity,
    completion: Completion<'_>,
    now_unix: i64,
) -> Result<()> {
    let (purpose, kind, context) = match completion {
        Completion::Triage => (Purpose::Triage, None, None),
        Completion::Delivery(context) => (Purpose::Ingest, Some("delivery"), Some(context)),
        Completion::Quarantine => (Purpose::Ingest, Some("quarantine"), None),
    };
    // Explicit CLI re-triage remains permitted; it never changes Ingest.
    if purpose == Purpose::Ingest {
        ensure!(
            matches!(
                state(conn, identity, purpose, context)?,
                SeenState::Unseen | SeenState::Seen
            ),
            "email completion requires explicit reconciliation"
        );
    }
    let input = (purpose == Purpose::Ingest).then_some(identity.input_sha256.as_str());
    let context_hash = context.map(|value| value.sha256.as_str());
    conn.execute(
        "INSERT INTO idx_email_seen_scoped \
         (unit_sha256, purpose, first_seen_unix, input_sha256, completion_kind, context_sha256) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(unit_sha256, purpose) DO NOTHING",
        rusqlite::params![
            identity.unit_sha256,
            purpose.as_str(),
            now_unix,
            input,
            kind,
            context_hash
        ],
    )
    .context("record scoped email completion")?;
    let row = read_scoped(conn, identity, purpose)?
        .context("scoped email completion was not recorded")?;
    if purpose == Purpose::Ingest {
        ensure!(
            row.input_sha256.as_deref() == input
                && row.completion_kind.as_deref() == kind
                && row.context_sha256.as_deref() == context_hash,
            "scoped email completion differs from intended input, targets or disposition"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
