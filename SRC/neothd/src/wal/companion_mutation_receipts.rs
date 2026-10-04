//! Closed append-once audit receipts for Companion authority mutations.
//!
//! This deliberately uses the writer-owned authenticated-prefix transaction.
//! A missing receipt is useful only after the writer has closed its own tail
//! and the lookup has reported a complete authenticated prefix.  Callers must
//! keep their authority mutation pending on every other result.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};

pub(crate) const COMPANION_MUTATION_RECEIPT_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CompanionMutationKind {
    Enroll,
    Revoke,
}

/// Public, redacted descriptor.  It contains neither a bearer, a device key,
/// nor an endpoint: `key_sha256` is the already persisted public fingerprint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompanionMutationReceiptDescriptor {
    pub(crate) schema_version: u8,
    pub(crate) mutation_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) revision: u64,
    pub(crate) kind: CompanionMutationKind,
    pub(crate) key_sha256: String,
}

impl CompanionMutationReceiptDescriptor {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == COMPANION_MUTATION_RECEIPT_SCHEMA_VERSION,
            "unsupported companion mutation receipt schema"
        );
        ensure!(self.revision > 0, "companion mutation receipt revision is zero");
        ensure!(
            self.key_sha256.len() == 64
                && self.key_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                && self.key_sha256.bytes().all(|byte| !byte.is_ascii_uppercase()),
            "companion mutation receipt key fingerprint is not lowercase SHA-256"
        );
        Ok(())
    }

    pub(crate) fn payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("encode companion mutation receipt")
    }

    pub(crate) fn header(&self, payload: &[u8]) -> crate::wal::EventHeaderV2 {
        crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, payload)
            .event_subtype(ExtendedSubtype::CompanionMutationReceipt as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompanionMutationReceiptOutcome {
    ExistingExact,
    AppendedExact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompanionMutationReceiptError {
    Conflict,
    Duplicate,
    Indeterminate,
}

/// A closed recovery classification.  `AbsentComplete` is the sole state that
/// permits the writer to create a new physical receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompanionMutationReceiptLookup {
    Exact,
    AbsentComplete,
    Conflict,
    Duplicate,
    Incomplete,
}

pub(crate) fn decode(payload: &[u8]) -> Result<CompanionMutationReceiptDescriptor> {
    let descriptor: CompanionMutationReceiptDescriptor =
        serde_json::from_slice(payload).context("decode companion mutation receipt")?;
    descriptor.validate()?;
    Ok(descriptor)
}

/// Scan only authenticated primary-WAL bytes.  Any malformed companion
/// receipt, unreadable segment, unsealed tail, or scan cap is returned as an
/// error so the writer maps it to `Indeterminate` rather than absence.
pub(crate) fn lookup_exact_at_home(
    home: &std::path::Path,
    expected: &CompanionMutationReceiptDescriptor,
) -> Result<CompanionMutationReceiptLookup> {
    expected.validate()?;
    let mut exact = 0usize;
    let mut conflict = false;
    let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        crate::wal::scan::supported_home_scan_limits(),
        |_, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::CompanionMutationReceipt as u8
            {
                return Ok(());
            }
            let observed = decode(frame.payload)
                .context("malformed companion mutation receipt in authenticated WAL")?;
            if observed.mutation_id == expected.mutation_id {
                if observed == *expected {
                    exact = exact.saturating_add(1);
                } else {
                    conflict = true;
                }
            }
            Ok(())
        },
    )
    .context("lookup companion mutation receipt in authenticated primary WAL")?;
    if !scan.complete {
        return Ok(CompanionMutationReceiptLookup::Incomplete);
    }
    if conflict {
        Ok(CompanionMutationReceiptLookup::Conflict)
    } else if exact > 1 {
        Ok(CompanionMutationReceiptLookup::Duplicate)
    } else if exact == 1 {
        Ok(CompanionMutationReceiptLookup::Exact)
    } else {
        Ok(CompanionMutationReceiptLookup::AbsentComplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> CompanionMutationReceiptDescriptor {
        CompanionMutationReceiptDescriptor {
            schema_version: COMPANION_MUTATION_RECEIPT_SCHEMA_VERSION,
            mutation_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            revision: 1,
            kind: CompanionMutationKind::Enroll,
            key_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn descriptor_is_public_redacted_and_round_trips_exactly() {
        let descriptor = descriptor();
        let payload = descriptor.payload().expect("bounded public descriptor encodes");
        assert!(!String::from_utf8_lossy(&payload).contains("bearer"));
        assert!(!String::from_utf8_lossy(&payload).contains("signing_key"));
        assert_eq!(decode(&payload).expect("typed decode"), descriptor);
    }

    #[test]
    fn descriptor_rejects_unbound_or_noncanonical_fingerprint() {
        let mut invalid = descriptor();
        invalid.revision = 0;
        assert!(invalid.validate().is_err());
        invalid.revision = 1;
        invalid.key_sha256 = "A".repeat(64);
        assert!(invalid.validate().is_err());
    }
}
