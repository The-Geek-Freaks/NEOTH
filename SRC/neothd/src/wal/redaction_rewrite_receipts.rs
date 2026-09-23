//! Closed authenticated-primary-WAL receipts for completed LEAF redaction rewrites.
//!
//! The descriptor contains only immutable operation and digest bindings.  It
//! deliberately excludes erased frame payloads, text, paths, and raw offsets.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use super::frame::encode_frame;
use super::header::EventHeaderV2;

pub(crate) const REDACTION_REWRITE_RECEIPT_SCHEMA_VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 224;

/// Domain-separated, content-free identity for the local-only target name and
/// immutable segment coordinates. The name is never placed in the receipt.
pub(crate) fn derive_target_identity_sha256(
    canonical_segment_name: &str,
    generation: u32,
    sequence: u64,
    start_ts_ns: u64,
    node_id: [u8; 16],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"neoth/redaction-rewrite-target-identity/v1\0");
    digest.update((canonical_segment_name.len() as u64).to_be_bytes());
    digest.update(canonical_segment_name.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(start_ts_ns.to_be_bytes());
    digest.update(node_id);
    digest.finalize().into()
}

/// Stable local-home binding for a rewrite descriptor. The canonical path is
/// hashed before persistence, so the receipt and journal contain no raw home.
pub(crate) fn derive_home_binding_sha256(home: &Path) -> std::io::Result<[u8; 32]> {
    let canonical = std::fs::canonicalize(home)?;
    let bytes = canonical.to_string_lossy();
    let mut digest = Sha256::new();
    digest.update(b"neoth/redaction-rewrite-home-binding/v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes.as_bytes());
    Ok(digest.finalize().into())
}

/// Canonical content-free identity of one completed authenticated LEAF rewrite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RedactionRewriteReceiptDescriptor {
    operation_id: [u8; 32],
    home_binding_sha256: [u8; 32],
    target_identity_sha256: [u8; 32],
    old_target_sha256: [u8; 32],
    new_target_sha256: [u8; 32],
    offset_summary_sha256: [u8; 32],
    affected_frame_count: u64,
    old_target_len: u64,
    new_target_len: u64,
}

impl RedactionRewriteReceiptDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        operation_id: [u8; 32],
        home_binding_sha256: [u8; 32],
        target_identity_sha256: [u8; 32],
        old_target_sha256: [u8; 32],
        new_target_sha256: [u8; 32],
        offset_summary_sha256: [u8; 32],
        affected_frame_count: u64,
        old_target_len: u64,
        new_target_len: u64,
    ) -> Result<Self, RedactionRewriteOnceError> {
        if operation_id == [0; 32]
            || home_binding_sha256 == [0; 32]
            || target_identity_sha256 == [0; 32]
            || old_target_sha256 == [0; 32]
            || new_target_sha256 == [0; 32]
            || offset_summary_sha256 == [0; 32]
            || affected_frame_count == 0
            || old_target_len == 0
            || new_target_len == 0
            || old_target_sha256 == new_target_sha256
        {
            return Err(RedactionRewriteOnceError::InvalidDescriptor);
        }
        Ok(Self {
            operation_id,
            home_binding_sha256,
            target_identity_sha256,
            old_target_sha256,
            new_target_sha256,
            offset_summary_sha256,
            affected_frame_count,
            old_target_len,
            new_target_len,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&[
            REDACTION_REWRITE_RECEIPT_SCHEMA_VERSION,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        for value in [
            self.operation_id,
            self.home_binding_sha256,
            self.target_identity_sha256,
            self.old_target_sha256,
            self.new_target_sha256,
            self.offset_summary_sha256,
        ] {
            payload.extend_from_slice(&value);
        }
        payload.extend_from_slice(&self.affected_frame_count.to_be_bytes());
        payload.extend_from_slice(&self.old_target_len.to_be_bytes());
        payload.extend_from_slice(&self.new_target_len.to_be_bytes());
        payload
    }

    pub(crate) fn decode_canonical(payload: &[u8]) -> Result<Self, RedactionRewriteOnceError> {
        if payload.len() != PAYLOAD_LEN
            || payload[0] != REDACTION_REWRITE_RECEIPT_SCHEMA_VERSION
            || payload[1..8] != [0; 7]
        {
            return Err(RedactionRewriteOnceError::InvalidDescriptor);
        }
        let mut hashes = [[0_u8; 32]; 6];
        for (index, hash) in hashes.iter_mut().enumerate() {
            let start = 8 + index * 32;
            hash.copy_from_slice(&payload[start..start + 32]);
        }
        let count = u64::from_be_bytes(payload[200..208].try_into().expect("fixed payload slice"));
        let old_len =
            u64::from_be_bytes(payload[208..216].try_into().expect("fixed payload slice"));
        let new_len =
            u64::from_be_bytes(payload[216..224].try_into().expect("fixed payload slice"));
        Self::new(
            hashes[0], hashes[1], hashes[2], hashes[3], hashes[4], hashes[5], count, old_len,
            new_len,
        )
    }

    pub(crate) fn header(&self) -> EventHeaderV2 {
        let payload = self.encode();
        crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::RedactionRewriteReceipt as u8)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build()
    }

    pub(crate) const fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }
    pub(crate) const fn home_binding_sha256(&self) -> [u8; 32] {
        self.home_binding_sha256
    }
    pub(crate) const fn target_identity_sha256(&self) -> [u8; 32] {
        self.target_identity_sha256
    }
    pub(crate) const fn old_target_sha256(&self) -> [u8; 32] {
        self.old_target_sha256
    }
    pub(crate) const fn new_target_sha256(&self) -> [u8; 32] {
        self.new_target_sha256
    }
    pub(crate) const fn offset_summary_sha256(&self) -> [u8; 32] {
        self.offset_summary_sha256
    }
    pub(crate) const fn affected_frame_count(&self) -> u64 {
        self.affected_frame_count
    }
    pub(crate) const fn old_target_len(&self) -> u64 {
        self.old_target_len
    }
    pub(crate) const fn new_target_len(&self) -> u64 {
        self.new_target_len
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RedactionRewriteFrameReceipt {
    frame_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    location_sha256: [u8; 32],
}

impl RedactionRewriteFrameReceipt {
    pub(crate) const fn frame_sha256(&self) -> [u8; 32] {
        self.frame_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RedactionRewriteOnceOutcome {
    ExistingExact(RedactionRewriteFrameReceipt),
    AppendedExact(RedactionRewriteFrameReceipt),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RedactionRewriteOnceError {
    #[error("redaction_rewrite_once_conflict")]
    Conflict,
    #[error("redaction_rewrite_once_duplicate")]
    Duplicate,
    #[error("redaction_rewrite_once_indeterminate")]
    Indeterminate,
    #[error("redaction_rewrite_once_invalid_descriptor")]
    InvalidDescriptor,
}

fn receipt_for(
    location: &super::scan::HomeWalFrameLocation,
    header: &EventHeaderV2,
    payload: &[u8],
) -> RedactionRewriteFrameReceipt {
    let frame: [u8; 32] = Sha256::digest(encode_frame(header, payload)).into();
    let payload_sha256: [u8; 32] = Sha256::digest(payload).into();
    let name = location.segment_name.to_string_lossy();
    let mut location_sha256 = Sha256::new();
    location_sha256.update(b"neoth/redaction-rewrite-receipt-location/v1\0");
    location_sha256.update((name.len() as u64).to_be_bytes());
    location_sha256.update(name.as_bytes());
    location_sha256.update(location.segment_generation.to_be_bytes());
    location_sha256.update(location.segment_seq.to_be_bytes());
    location_sha256.update(location.segment_start_ts_ns.to_be_bytes());
    location_sha256.update(location.segment_node_id);
    location_sha256.update(location.logical_offset.to_be_bytes());
    location_sha256.update(frame);
    RedactionRewriteFrameReceipt {
        frame_sha256: frame,
        payload_sha256,
        location_sha256: location_sha256.finalize().into(),
    }
}

pub(crate) enum Lookup {
    Exact(RedactionRewriteFrameReceipt),
    AbsentComplete,
    Conflict,
    Duplicate,
    Indeterminate,
}

/// A complete authenticated whole-home prefix is required for both replay and
/// absence decisions. Any malformed receipt or scan limit is indeterminate.
pub(crate) fn lookup_exact_at_home(
    home: &Path,
    expected: &RedactionRewriteReceiptDescriptor,
) -> Lookup {
    let mut exact = None;
    let mut count = 0usize;
    let mut conflict = false;
    let Ok(scan) = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |location, frame| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != ExtendedSubtype::RedactionRewriteReceipt as u8
            {
                return Ok(());
            }
            let observed = RedactionRewriteReceiptDescriptor::decode_canonical(frame.payload)
                .map_err(|_| {
                    anyhow::anyhow!("invalid redaction rewrite receipt in authenticated WAL")
                })?;
            if observed.operation_id != expected.operation_id {
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
    if !scan.complete {
        Lookup::Indeterminate
    } else if conflict {
        Lookup::Conflict
    } else if count > 1 {
        Lookup::Duplicate
    } else if let Some(receipt) = exact {
        Lookup::Exact(receipt)
    } else {
        Lookup::AbsentComplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(last: u8) -> RedactionRewriteReceiptDescriptor {
        RedactionRewriteReceiptDescriptor::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            3,
            100,
            80 + u64::from(last),
        )
        .unwrap()
    }

    #[test]
    fn canonical_payload_round_trips_and_has_no_erased_text() {
        let payload = descriptor(1).encode();
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert_eq!(
            RedactionRewriteReceiptDescriptor::decode_canonical(&payload).unwrap(),
            descriptor(1)
        );
        assert!(
            !payload
                .windows(b"erased".len())
                .any(|part| part == b"erased")
        );
    }

    #[test]
    fn descriptor_rejects_zero_operation_or_empty_affected_set() {
        assert_eq!(
            RedactionRewriteReceiptDescriptor::new(
                [0; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 1, 1, 1
            ),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
        assert_eq!(
            RedactionRewriteReceiptDescriptor::new(
                [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 0, 1, 1
            ),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
        assert_eq!(
            RedactionRewriteReceiptDescriptor::new(
                [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 1, 0, 1
            ),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
        assert_eq!(
            RedactionRewriteReceiptDescriptor::new(
                [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 1, 1, 0
            ),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
        assert_eq!(
            RedactionRewriteReceiptDescriptor::new(
                [1; 32], [2; 32], [3; 32], [4; 32], [4; 32], [6; 32], 1, 1, 1
            ),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
    }

    #[test]
    fn decoder_rejects_reserved_bytes_and_payload_drift() {
        let mut payload = descriptor(1).encode();
        payload[1] = 1;
        assert_eq!(
            RedactionRewriteReceiptDescriptor::decode_canonical(&payload),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
        assert_eq!(
            RedactionRewriteReceiptDescriptor::decode_canonical(&payload[..223]),
            Err(RedactionRewriteOnceError::InvalidDescriptor)
        );
    }

    #[test]
    fn target_identity_is_domain_separated_and_does_not_embed_the_name() {
        let identity = derive_target_identity_sha256("leaf-000001.wal", 7, 11, 13, [17; 16]);
        assert_ne!(
            identity,
            derive_target_identity_sha256("leaf-000002.wal", 7, 11, 13, [17; 16])
        );
        assert_ne!(identity.as_slice(), b"leaf-000001.wal");
    }
}
