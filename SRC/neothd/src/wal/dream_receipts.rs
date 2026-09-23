//! Closed authenticated-primary-WAL receipts for completed Dream phase transitions.
//!
//! The SQLite Dream outbox supplies an immutable descriptor.  This module never
//! accepts content, sender identifiers, or a caller-minted WAL header: the
//! writer owns authenticated lookup, conflict detection, and the sole append.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use super::frame::encode_frame;
use super::header::EventHeaderV2;

pub(crate) const DREAM_AUDIT_SCHEMA_VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DreamPhase {
    Light = 1,
    Rem = 2,
    Repair = 3,
}

impl DreamPhase {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Light),
            2 => Some(Self::Rem),
            3 => Some(Self::Repair),
            _ => None,
        }
    }
}

/// The WAL only audits an immutable, completed SQLite phase effect.  A pending
/// outbox is intentionally not emitted: absence of this frame remains pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DreamAuditState {
    Completed = 1,
}

impl DreamAuditState {
    fn from_u8(value: u8) -> Option<Self> {
        (value == Self::Completed as u8).then_some(Self::Completed)
    }
}

/// Canonical content-free binding owned by one `dream_phase_receipt` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DreamAuditDescriptor {
    transition_id: [u8; 32],
    run_id_hash: [u8; 32],
    phase: DreamPhase,
    state: DreamAuditState,
    result_sha256: [u8; 32],
}

impl DreamAuditDescriptor {
    pub(crate) fn new(
        transition_id: [u8; 32],
        run_id_hash: [u8; 32],
        phase: DreamPhase,
        state: DreamAuditState,
        result_sha256: [u8; 32],
    ) -> Result<Self, DreamAuditOnceError> {
        if transition_id == [0; 32] || run_id_hash == [0; 32] || result_sha256 == [0; 32] {
            return Err(DreamAuditOnceError::InvalidDescriptor);
        }
        Ok(Self {
            transition_id,
            run_id_hash,
            phase,
            state,
            result_sha256,
        })
    }

    pub(crate) const fn transition_id(&self) -> [u8; 32] {
        self.transition_id
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&[
            DREAM_AUDIT_SCHEMA_VERSION,
            self.phase as u8,
            self.state as u8,
            0,
        ]);
        payload.extend_from_slice(&self.transition_id);
        payload.extend_from_slice(&self.run_id_hash);
        payload.extend_from_slice(&self.result_sha256);
        payload
    }

    fn decode(payload: &[u8]) -> Result<Self, DreamAuditOnceError> {
        if payload.len() != PAYLOAD_LEN
            || payload[0] != DREAM_AUDIT_SCHEMA_VERSION
            || payload[3] != 0
        {
            return Err(DreamAuditOnceError::InvalidDescriptor);
        }
        let mut transition_id = [0; 32];
        let mut run_id_hash = [0; 32];
        let mut result_sha256 = [0; 32];
        transition_id.copy_from_slice(&payload[4..36]);
        run_id_hash.copy_from_slice(&payload[36..68]);
        result_sha256.copy_from_slice(&payload[68..100]);
        Self::new(
            transition_id,
            run_id_hash,
            DreamPhase::from_u8(payload[1]).ok_or(DreamAuditOnceError::InvalidDescriptor)?,
            DreamAuditState::from_u8(payload[2]).ok_or(DreamAuditOnceError::InvalidDescriptor)?,
            result_sha256,
        )
    }

    pub(crate) fn header(&self) -> EventHeaderV2 {
        let payload = self.encode();
        crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::DreamPhaseAudit as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DreamAuditFrameReceipt {
    frame_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    location_sha256: [u8; 32],
}

impl DreamAuditFrameReceipt {
    pub(crate) const fn frame_sha256(&self) -> [u8; 32] {
        self.frame_sha256
    }
    pub(crate) const fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }
    pub(crate) const fn location_sha256(&self) -> [u8; 32] {
        self.location_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DreamAuditOnceOutcome {
    ExistingExact(DreamAuditFrameReceipt),
    AppendedExact(DreamAuditFrameReceipt),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DreamAuditOnceError {
    #[error("dream_audit_once_conflict")]
    Conflict,
    #[error("dream_audit_once_duplicate")]
    Duplicate,
    #[error("dream_audit_once_indeterminate")]
    Indeterminate,
    #[error("dream_audit_once_invalid_descriptor")]
    InvalidDescriptor,
}

fn receipt_for(
    location: &super::scan::HomeWalFrameLocation,
    header: &EventHeaderV2,
    payload: &[u8],
) -> DreamAuditFrameReceipt {
    let frame = encode_frame(header, payload);
    let frame_sha256: [u8; 32] = Sha256::digest(frame).into();
    let payload_sha256: [u8; 32] = Sha256::digest(payload).into();
    let name = location.segment_name.to_string_lossy();
    let mut location_digest = Sha256::new();
    location_digest.update(b"neoth/dream-audit-location/v1\0");
    location_digest.update((name.len() as u64).to_be_bytes());
    location_digest.update(name.as_bytes());
    location_digest.update(location.segment_generation.to_be_bytes());
    location_digest.update(location.segment_seq.to_be_bytes());
    location_digest.update(location.segment_start_ts_ns.to_be_bytes());
    location_digest.update(location.segment_node_id);
    location_digest.update(location.logical_offset.to_be_bytes());
    location_digest.update(frame_sha256);
    DreamAuditFrameReceipt {
        frame_sha256,
        payload_sha256,
        location_sha256: location_digest.finalize().into(),
    }
}

pub(crate) enum Lookup {
    Exact(DreamAuditFrameReceipt),
    AbsentComplete,
    Conflict,
    Duplicate,
    Indeterminate,
}

/// Authenticated scan only.  Absence is not itself authorization to append;
/// the writer holds the matching home authority when turning it into a write.
pub(crate) fn lookup_exact_at_home(home: &Path, expected: &DreamAuditDescriptor) -> Lookup {
    let mut exact = None;
    let mut count = 0usize;
    let mut conflict = false;
    let Ok(scan) = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |location, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::DreamPhaseAudit as u8
            {
                return Ok(());
            }
            let observed = DreamAuditDescriptor::decode(frame.payload)
                .map_err(|_| anyhow::anyhow!("invalid Dream audit payload in authenticated WAL"))?;
            if observed.transition_id != expected.transition_id {
                return Ok(());
            }
            if observed == *expected {
                count = count.saturating_add(1);
                if exact.is_none() {
                    exact = Some(receipt_for(location, &frame.header, frame.payload));
                }
            } else {
                conflict = true;
            }
            Ok(())
        },
    ) else {
        return Lookup::Indeterminate;
    };
    if conflict {
        Lookup::Conflict
    } else if count > 1 {
        Lookup::Duplicate
    } else if let Some(receipt) = exact {
        Lookup::Exact(receipt)
    } else if scan.complete {
        Lookup::AbsentComplete
    } else {
        Lookup::Indeterminate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> DreamAuditDescriptor {
        DreamAuditDescriptor::new(
            [1; 32],
            [2; 32],
            DreamPhase::Light,
            DreamAuditState::Completed,
            [3; 32],
        )
        .unwrap()
    }

    #[test]
    fn canonical_payload_round_trips_and_excludes_text_fields() {
        let descriptor = descriptor();
        let payload = descriptor.encode();
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert_eq!(DreamAuditDescriptor::decode(&payload).unwrap(), descriptor);
        assert!(
            !payload
                .windows(b"sender".len())
                .any(|bytes| bytes == b"sender")
        );
    }

    #[test]
    fn descriptor_rejects_zero_identity_or_noncanonical_reserved_byte() {
        assert!(
            DreamAuditDescriptor::new(
                [0; 32],
                [2; 32],
                DreamPhase::Light,
                DreamAuditState::Completed,
                [3; 32]
            )
            .is_err()
        );
        let mut payload = descriptor().encode();
        payload[3] = 1;
        assert_eq!(
            DreamAuditDescriptor::decode(&payload),
            Err(DreamAuditOnceError::InvalidDescriptor)
        );
    }
}
