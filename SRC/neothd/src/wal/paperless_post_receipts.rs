//! Authenticated pre-send claims and observed document-completion receipts.
//!
//! Both transitions use the daemon's existing writer. A complete receipt proves
//! the document's exact original bytes were observed during reconciliation; it
//! does not promise continued existence after another Paperless actor deletes it.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};

pub(crate) const PAPERLESS_POST_INTENT_SCHEMA_VERSION: u8 = 1;
pub(crate) const MAX_OPEN_PAPERLESS_INTENTS: usize = 128;

/// Shared mailbox-unit identity. Preserve the v1 bytes for existing WAL claims.
#[cfg(any(test, feature = "imap_fetch"))]
pub(crate) fn mail_unit_sha256(host: &str, port: u16, username: &str, mail_key: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    digest_parts(
        b"neoth.paperless.mail-unit.v1\0",
        &[
            host.as_bytes(),
            &port.to_le_bytes(),
            username.as_bytes(),
            b"INBOX",
            mail_key.as_bytes(),
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hex::encode(hash.finalize())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PaperlessCompletion {
    document_id: u64,
    body_sha256: String,
    marker_sha256: String,
}

/// A unit identifies one mailbox message, separately from its requested effect.
/// Changing body, title or destination cannot manufacture a new send authority.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PaperlessPostIntentDescriptor {
    pub(crate) schema_version: u8,
    pub(crate) unit_sha256: String,
    pub(crate) body_sha256: String,
    pub(crate) title_sha256: String,
    pub(crate) destination_sha256: String,
    completion: Option<PaperlessCompletion>,
}

impl PaperlessPostIntentDescriptor {
    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn from_mail(
        host: &str,
        port: u16,
        username: &str,
        mail_key: &str,
        body: &str,
        title: &str,
        destination: &str,
    ) -> Self {
        Self {
            schema_version: PAPERLESS_POST_INTENT_SCHEMA_VERSION,
            unit_sha256: mail_unit_sha256(host, port, username, mail_key),
            body_sha256: hex::encode(Sha256::digest(body.as_bytes())),
            title_sha256: digest_parts(b"neoth.paperless.title.v1\0", &[title.as_bytes()]),
            destination_sha256: digest_parts(
                b"neoth.paperless.destination.v1\0",
                &[destination.as_bytes()],
            ),
            completion: None,
        }
    }

    pub(crate) fn marker_filename(&self) -> String {
        let binding = digest_parts(
            b"neoth.paperless.original-filename.v1\0",
            &[
                self.unit_sha256.as_bytes(),
                self.body_sha256.as_bytes(),
                self.title_sha256.as_bytes(),
                self.destination_sha256.as_bytes(),
            ],
        );
        format!("neoth-{binding}.txt")
    }

    pub(crate) fn is_completion(&self) -> bool {
        self.completion.is_some()
    }

    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn with_verified_document(
        &self,
        document_id: u64,
        original_sha256: &str,
    ) -> Result<Self> {
        self.validate()?;
        ensure!(
            !self.is_completion() && document_id > 0,
            "invalid paperless completion transition"
        );
        ensure!(
            original_sha256 == self.body_sha256,
            "paperless original content mismatch"
        );
        let mut completed = self.clone();
        completed.completion = Some(PaperlessCompletion {
            document_id,
            body_sha256: original_sha256.to_owned(),
            marker_sha256: hex::encode(Sha256::digest(self.marker_filename().as_bytes())),
        });
        completed.validate()?;
        Ok(completed)
    }

    fn same_request(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.unit_sha256 == other.unit_sha256
            && self.body_sha256 == other.body_sha256
            && self.title_sha256 == other.title_sha256
            && self.destination_sha256 == other.destination_sha256
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == PAPERLESS_POST_INTENT_SCHEMA_VERSION,
            "unsupported paperless post receipt schema"
        );
        for value in [
            &self.unit_sha256,
            &self.body_sha256,
            &self.title_sha256,
            &self.destination_sha256,
        ] {
            ensure!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "paperless post receipt fingerprint is not lowercase SHA-256"
            );
        }
        if let Some(completed) = &self.completion {
            ensure!(
                completed.document_id > 0
                    && completed.body_sha256 == self.body_sha256
                    && completed.marker_sha256
                        == hex::encode(Sha256::digest(self.marker_filename().as_bytes())),
                "paperless completion witness does not match the request"
            );
        }
        Ok(())
    }

    pub(crate) fn payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("encode paperless post receipt")
    }

    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn header(&self, payload: &[u8]) -> crate::wal::EventHeaderV2 {
        crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, payload)
            .event_subtype(ExtendedSubtype::PaperlessPostReceipt as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaperlessPostIntentOutcome {
    Existing,
    Appended,
    Completed(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaperlessPostIntentError {
    Conflict,
    Duplicate,
    Capacity,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaperlessPostIntentLookup {
    Exact,
    CompletedExact(u64),
    AbsentComplete,
    Conflict,
    Duplicate,
    Capacity,
    Incomplete,
}

pub(crate) fn decode(payload: &[u8]) -> Result<PaperlessPostIntentDescriptor> {
    let descriptor: PaperlessPostIntentDescriptor =
        serde_json::from_slice(payload).context("decode paperless post receipt")?;
    descriptor.validate()?;
    Ok(descriptor)
}

fn track_open_receipt(
    open: &mut std::collections::HashMap<String, PaperlessPostIntentDescriptor>,
    observed: &PaperlessPostIntentDescriptor,
) -> Result<()> {
    if observed.is_completion() {
        let intent = open
            .get(&observed.unit_sha256)
            .context("paperless completion lacks a preceding open intent")?;
        ensure!(
            intent.same_request(observed),
            "paperless completion differs from preceding intent binding"
        );
        open.remove(&observed.unit_sha256);
    } else {
        ensure!(
            !open.contains_key(&observed.unit_sha256),
            "duplicate open paperless intent"
        );
        ensure!(
            open.len() < MAX_OPEN_PAPERLESS_INTENTS,
            "paperless pending bound exceeded"
        );
        open.insert(observed.unit_sha256.clone(), observed.clone());
    }
    Ok(())
}

/// Only the writer calls this under its exclusive authority after sealing the
/// current tail. The open set is bounded and is reconstructed from primary WAL;
/// neither a cache nor views.db can grant an upload or a completion.
pub(crate) fn lookup_exact_at_home(
    home: &std::path::Path,
    expected: &PaperlessPostIntentDescriptor,
) -> Result<PaperlessPostIntentLookup> {
    expected.validate()?;
    let mut intents = 0usize;
    let mut completions = 0usize;
    let mut completed = None;
    let mut conflict = false;
    let mut open = std::collections::HashMap::new();
    let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        crate::wal::scan::supported_home_scan_limits(),
        |_, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::PaperlessPostReceipt as u8
            {
                return Ok(());
            }
            let observed = decode(frame.payload)
                .context("malformed paperless post receipt in authenticated WAL")?;
            track_open_receipt(&mut open, &observed)?;
            if observed.unit_sha256 == expected.unit_sha256 {
                if !observed.same_request(expected) {
                    conflict = true;
                }
                if let Some(witness) = observed.completion {
                    completions = completions.saturating_add(1);
                    if intents != 1 {
                        conflict = true;
                    }
                    completed = Some(witness);
                } else {
                    intents = intents.saturating_add(1);
                    if completions != 0 {
                        conflict = true;
                    }
                }
            }
            Ok(())
        },
    )
    .context("lookup paperless receipts in authenticated primary WAL")?;
    use PaperlessPostIntentLookup as Lookup;
    if !scan.complete {
        return Ok(Lookup::Incomplete);
    }
    if conflict {
        return Ok(Lookup::Conflict);
    }
    if intents > 1 || completions > 1 {
        return Ok(Lookup::Duplicate);
    }
    if let Some(witness) = expected.completion.as_ref() {
        if intents != 1 {
            return Ok(Lookup::Conflict);
        }
        return Ok(match completed {
            Some(observed) if observed == *witness => Lookup::Exact,
            Some(_) => Lookup::Conflict,
            None => Lookup::AbsentComplete,
        });
    }
    if let Some(witness) = completed {
        return Ok(Lookup::CompletedExact(witness.document_id));
    }
    if intents == 1 {
        return Ok(Lookup::Exact);
    }
    if open.len() >= MAX_OPEN_PAPERLESS_INTENTS {
        return Ok(Lookup::Capacity);
    }
    Ok(Lookup::AbsentComplete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paperless_descriptor_separates_unit_identity_from_request_drift_and_private_text() {
        let original = PaperlessPostIntentDescriptor::from_mail(
            "MAIL.EXAMPLE.",
            993,
            "PRIVATE_USER",
            "PRIVATE_MAIL",
            "PRIVATE_BODY",
            "PRIVATE_TITLE",
            "http://private.invalid/api/documents/post_document/",
        );
        let changed = PaperlessPostIntentDescriptor::from_mail(
            "mail.example",
            993,
            "PRIVATE_USER",
            "PRIVATE_MAIL",
            "different body",
            "different title",
            "http://other.invalid/api/documents/post_document/",
        );
        assert_eq!(original.unit_sha256, changed.unit_sha256);
        assert_ne!(original.body_sha256, changed.body_sha256);
        assert_ne!(original.title_sha256, changed.title_sha256);
        assert_ne!(original.destination_sha256, changed.destination_sha256);
        let other_mail = PaperlessPostIntentDescriptor::from_mail(
            "mail.example",
            993,
            "PRIVATE_USER",
            "other-mail",
            "PRIVATE_BODY",
            "PRIVATE_TITLE",
            "http://private.invalid/api/documents/post_document/",
        );
        assert_ne!(original.unit_sha256, other_mail.unit_sha256);
        let payload = original.payload().unwrap();
        assert_eq!(decode(&payload).unwrap(), original);
        let rendered = String::from_utf8(payload).unwrap();
        for private in ["PRIVATE_", "private.invalid", "other.invalid"] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    fn paperless_completion_cannot_release_capacity_for_a_different_open_binding() {
        let intent = PaperlessPostIntentDescriptor::from_mail(
            "mail.example",
            993,
            "u",
            "m",
            "body",
            "title",
            "http://p.invalid/",
        );
        let mut open = std::collections::HashMap::new();
        track_open_receipt(&mut open, &decode(&intent.payload().unwrap()).unwrap()).unwrap();
        let mut drift = intent.clone();
        drift.body_sha256 = "a".repeat(64);
        let wrong = drift.with_verified_document(7, &drift.body_sha256).unwrap();
        assert!(
            track_open_receipt(&mut open, &decode(&wrong.payload().unwrap()).unwrap()).is_err()
        );
        assert_eq!(open.get(&intent.unit_sha256), Some(&intent));
        let complete = intent
            .with_verified_document(7, &intent.body_sha256)
            .unwrap();
        track_open_receipt(&mut open, &decode(&complete.payload().unwrap()).unwrap()).unwrap();
        assert!(open.is_empty());
        assert!(track_open_receipt(&mut open, &complete).is_err());
    }

    #[test]
    fn paperless_descriptor_rejects_noncanonical_or_unknown_schema() {
        let mut value = PaperlessPostIntentDescriptor::from_mail(
            "mail.example",
            993,
            "u",
            "m",
            "body",
            "title",
            "http://p.invalid/",
        );
        value.title_sha256 = "A".repeat(64);
        assert!(value.validate().is_err());
        value.title_sha256 = "a".repeat(64);
        value.schema_version = 0;
        assert!(value.validate().is_err());
    }
}
