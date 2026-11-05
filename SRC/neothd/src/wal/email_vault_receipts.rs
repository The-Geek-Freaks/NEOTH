//! Ordered, authenticated note-content claims. Directory preparation precedes
//! Intent; no rendition byte may precede FileBound. These receipts do not grant
//! authority to replace an existing note or repair a partial write.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};

const MAX_OPEN_NOTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) enum Stage {
    Intent,
    FileBound,
    Completed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    schema_version: u8,
    pub(crate) unit_sha256: String,
    input_sha256: String,
    rendition_sha256: String,
    directory_sha256: String,
    pub(crate) stage: Stage,
    pub(crate) file_identity: Option<String>,
}

impl Descriptor {
    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn intent(unit: &str, input: &str, rendition: &str, directory: &str) -> Result<Self> {
        let value = Self {
            schema_version: 1,
            unit_sha256: unit.into(),
            input_sha256: input.into(),
            rendition_sha256: rendition.into(),
            directory_sha256: directory.into(),
            stage: Stage::Intent,
            file_identity: None,
        };
        value.validate()?;
        Ok(value)
    }

    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn bind_file(&self, identity: &str) -> Result<Self> {
        ensure!(self.stage == Stage::Intent, "note file binding requires intent");
        let mut value = self.clone();
        value.stage = Stage::FileBound;
        value.file_identity = Some(identity.into());
        value.validate()?;
        Ok(value)
    }

    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn completed(&self) -> Result<Self> {
        ensure!(self.stage == Stage::FileBound, "note completion requires file binding");
        let mut value = self.clone();
        value.stage = Stage::Completed;
        value.validate()?;
        Ok(value)
    }

    fn same_request(&self, other: &Self) -> bool {
        self.unit_sha256 == other.unit_sha256
            && self.input_sha256 == other.input_sha256
            && self.rendition_sha256 == other.rendition_sha256
            && self.directory_sha256 == other.directory_sha256
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported email vault receipt schema");
        for value in [&self.unit_sha256, &self.input_sha256, &self.rendition_sha256, &self.directory_sha256] {
            ensure!(value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()), "invalid email vault fingerprint");
        }
        match (&self.stage, &self.file_identity) {
            (Stage::Intent, None) => {}
            (Stage::FileBound | Stage::Completed, Some(token)) => {
                ensure!(crate::skills::store::valid_child_identity_token(token) && token.ends_with(":file"), "invalid email vault file identity");
            }
            _ => anyhow::bail!("email vault stage lacks its exact file binding"),
        }
        Ok(())
    }

    pub(crate) fn payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("encode email vault receipt")
    }

    #[cfg(any(test, feature = "imap_fetch"))]
    pub(crate) fn header(&self, payload: &[u8]) -> super::EventHeaderV2 {
        super::HeaderBuilder::new(EVENT_TYPE_EXTENDED, payload)
            .event_subtype(ExtendedSubtype::EmailVaultReceipt as u8)
            .flags(super::EventFlags::SYNTHETIC)
            .build()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Appended,
    Existing(Descriptor),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Conflict,
    Capacity,
    Indeterminate,
}

pub(crate) enum Lookup {
    Existing(Descriptor),
    AbsentComplete,
    Conflict,
    Capacity,
    Incomplete,
}

fn follows(previous: &Descriptor, next: &Descriptor) -> bool {
    previous.same_request(next)
        && match (previous.stage, next.stage) {
            (Stage::Intent, Stage::FileBound) => true,
            (Stage::FileBound, Stage::Completed) => previous.file_identity == next.file_identity,
            _ => false,
        }
}

fn decide(observed: Option<Descriptor>, expected: &Descriptor, open_count: usize) -> Lookup {
    let Some(observed) = observed else {
        return if expected.stage != Stage::Intent {
            Lookup::Conflict
        } else if open_count >= MAX_OPEN_NOTES {
            Lookup::Capacity
        } else {
            Lookup::AbsentComplete
        };
    };
    if !observed.same_request(expected) {
        return Lookup::Conflict;
    }
    if expected.stage == Stage::Intent || observed == *expected
        || (expected.stage == Stage::FileBound && observed.stage == Stage::Completed
            && expected.file_identity == observed.file_identity)
    {
        Lookup::Existing(observed)
    } else if follows(&observed, expected) {
        Lookup::AbsentComplete
    } else {
        Lookup::Conflict
    }
}

/// Called only by the writer under its email claim authority, after sealing its
/// tail. A bounded primary-WAL scan, never a views row, grants each transition.
pub(crate) fn lookup_exact_at_home(home: &std::path::Path, expected: &Descriptor) -> Result<Lookup> {
    expected.validate()?;
    let mut open: std::collections::HashMap<String, Descriptor> = std::collections::HashMap::new();
    let mut latest: Option<Descriptor> = None;
    let scan = super::scan::for_each_authenticated_prefix_frame_at_home(
        home, super::scan::supported_home_scan_limits(), |_, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::EmailVaultReceipt as u8
            {
                return Ok(());
            }
            let value: Descriptor = serde_json::from_slice(frame.payload).context("decode email vault receipt")?;
            value.validate()?;
            if value.stage == Stage::Intent {
                ensure!(!open.contains_key(&value.unit_sha256) && open.len() < MAX_OPEN_NOTES, "duplicate or excessive open email vault claims");
                open.insert(value.unit_sha256.clone(), value.clone());
            } else {
                let preceding = open.get(&value.unit_sha256).context("email vault transition lacks intent")?;
                ensure!(follows(preceding, &value), "email vault transition changes binding or skips a stage");
                if value.stage == Stage::Completed {
                    open.remove(&value.unit_sha256);
                } else {
                    open.insert(value.unit_sha256.clone(), value.clone());
                }
            }
            if value.unit_sha256 == expected.unit_sha256 {
                if let Some(previous) = latest.as_ref() {
                    ensure!(follows(previous, &value), "duplicate or reopened email vault unit");
                }
                latest = Some(value);
            }
            Ok(())
        },
    )?;
    if !scan.complete {
        return Ok(Lookup::Incomplete);
    }
    Ok(decide(latest, expected, open.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> Descriptor {
        Descriptor::intent(&"a".repeat(64), &"b".repeat(64), &"c".repeat(64), &"d".repeat(64)).unwrap()
    }

    #[test]
    fn vault_receipt_schema_and_transition_gate_reject_drift_and_capacity() {
        let original = intent();
        let bound = original.bind_file("unix:0000000000000001:0000000000000002:file").unwrap();
        let completed = bound.completed().unwrap();
        assert!(original.completed().is_err());
        assert!(bound.bind_file("unix:0000000000000001:0000000000000002:file").is_err());
        assert!(matches!(decide(None, &original, MAX_OPEN_NOTES), Lookup::Capacity));
        assert!(matches!(decide(None, &bound, 0), Lookup::Conflict));
        assert!(matches!(decide(Some(original.clone()), &completed, 1), Lookup::Conflict));
        for field in 0..3 {
            let mut changed = original.clone();
            match field {
                0 => changed.input_sha256 = "e".repeat(64),
                1 => changed.rendition_sha256 = "e".repeat(64),
                _ => changed.directory_sha256 = "e".repeat(64),
            }
            assert!(matches!(decide(Some(completed.clone()), &changed, 0), Lookup::Conflict));
        }
        for token in ["", "unix:0000000000000001:0000000000000002:dir", "private raw path"] {
            assert!(original.bind_file(token).is_err());
        }
        let mut malformed = original.clone();
        malformed.schema_version = 2;
        assert!(malformed.payload().is_err());
        malformed = original.clone();
        malformed.input_sha256 = "A".repeat(64);
        assert!(malformed.payload().is_err());
        malformed = original;
        malformed.file_identity = bound.file_identity;
        assert!(malformed.payload().is_err());
    }

    #[tokio::test]
    async fn vault_writer_orders_and_reconciles_exact_receipts_across_restart() {
        let (writer, join, home, segment) = super::super::writer::spawn_isolated_ready_test_writer("vault-receipts").await.unwrap();
        let original = intent();
        let bound = original.bind_file("unix:0000000000000001:0000000000000002:file").unwrap();
        let completed = bound.completed().unwrap();
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), bound.clone()).await, Err(Error::Conflict));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), original.clone()).await, Ok(Outcome::Appended));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), completed.clone()).await, Err(Error::Conflict));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), bound.clone()).await, Ok(Outcome::Appended));
        let wrong = original.bind_file("unix:0000000000000001:0000000000000003:file").unwrap();
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), wrong).await, Err(Error::Conflict));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), completed.clone()).await, Ok(Outcome::Appended));
        drop(writer);
        join.await.unwrap().unwrap();
        let (writer, join, ready) = super::super::writer::spawn_for_home_ready(segment, home.path().to_path_buf()).unwrap();
        ready.wait().await.unwrap();
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), original).await, Ok(Outcome::Existing(completed.clone())));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), bound).await, Ok(Outcome::Existing(completed.clone())));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), completed.clone()).await, Ok(Outcome::Existing(completed)));
        drop(writer);
        join.await.unwrap().unwrap();
        let mut count = 0;
        let scan = super::super::scan::for_each_authenticated_prefix_frame_at_home(home.path(), super::super::scan::supported_home_scan_limits(), |_, frame| {
            if frame.header.event_type == EVENT_TYPE_EXTENDED && frame.header.event_subtype == ExtendedSubtype::EmailVaultReceipt as u8 { count += 1; }
            Ok(())
        }).unwrap();
        assert!(scan.complete);
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn vault_writer_rejects_generic_append_foreign_home_and_closed_writer() {
        let (writer, join, home, _) = super::super::writer::spawn_isolated_ready_test_writer("vault-closed-api").await.unwrap();
        let original = intent();
        let payload = original.payload().unwrap();
        assert!(writer.append(original.header(&payload), payload).await.is_err());
        let foreign = tempfile::tempdir().unwrap();
        assert_eq!(writer.append_email_vault_receipt_once(foreign.path(), original.clone()).await, Err(Error::Indeterminate));
        assert_eq!(writer.append_email_vault_receipt_once(home.path(), original.clone()).await, Ok(Outcome::Appended));
        drop(writer);
        join.await.unwrap().unwrap();
        let closed = super::super::writer::closed_test_writer();
        assert_eq!(closed.append_email_vault_receipt_once(home.path(), original).await, Err(Error::Indeterminate));
    }
}
