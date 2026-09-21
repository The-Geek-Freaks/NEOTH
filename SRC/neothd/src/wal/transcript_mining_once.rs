//! Closed authenticated-primary-WAL descriptors for transcript-mining proof frames.
//!
//! These descriptors are deliberately constructed from already-persisted bytes.
//! They are not a general WAL-frame API: the writer owns lookup, optional append,
//! marker closure, and the terminal receipt.

use std::path::Path;

use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};

use super::events::{EVENT_TYPE_EXTENDED, EVENT_TYPE_RAW_TEXT, ExtendedSubtype};
use super::frame::encode_frame;
use super::header::{EventHeaderV2, HEADER_BODY_LEN};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TranscriptMiningOnceError {
    #[error("transcript_mining_once_conflict")]
    Conflict,
    #[error("transcript_mining_once_duplicate")]
    Duplicate,
    #[error("transcript_mining_once_indeterminate")]
    Indeterminate,
    #[error("transcript_mining_once_expired_absent")]
    ExpiredAbsent(ExpiredMiningFrameReceipt),
}

/// Evidence that the writer, while holding transcript-mining authority, saw a
/// complete authenticated absence and refused an already-expired Bound frame.
/// It has no physical-frame location because no frame was appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredMiningFrameReceipt {
    operation_descriptor_sha256: [u8; 32],
    header_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    observed_at_unix: i64,
}

impl ExpiredMiningFrameReceipt {
    pub(crate) const fn operation_descriptor_sha256(&self) -> [u8; 32] {
        self.operation_descriptor_sha256
    }
    pub(crate) const fn header_sha256(&self) -> [u8; 32] {
        self.header_sha256
    }
    pub(crate) const fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }
    pub(crate) const fn observed_at_unix(&self) -> i64 {
        self.observed_at_unix
    }
}

/// Metadata-only proof returned after an authenticated exact frame lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TranscriptMiningFrameReceipt {
    header_sha256: [u8; 32],
    frame_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    location_sha256: [u8; 32],
}

impl TranscriptMiningFrameReceipt {
    pub(crate) const fn header_sha256(&self) -> [u8; 32] {
        self.header_sha256
    }
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

#[derive(Clone)]
struct PersistedFrameDescriptor {
    header: EventHeaderV2,
    header_bytes: [u8; HEADER_BODY_LEN],
    header_sha256: [u8; 32],
    payload: Vec<u8>,
    payload_sha256: [u8; 32],
}

impl PersistedFrameDescriptor {
    fn from_persisted(
        header_bytes: &[u8],
        header_sha256: [u8; 32],
        payload: Vec<u8>,
        payload_sha256: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            header_bytes.len() == HEADER_BODY_LEN,
            "transcript mining planned header length"
        );
        let computed_header_sha: [u8; 32] = Sha256::digest(header_bytes).into();
        let computed_payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        ensure!(
            computed_header_sha == header_sha256,
            "transcript mining planned header digest"
        );
        ensure!(
            computed_payload_sha == payload_sha256,
            "transcript mining payload digest"
        );
        let mut bytes = [0_u8; HEADER_BODY_LEN];
        bytes.copy_from_slice(header_bytes);
        let header = EventHeaderV2::from_le_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("transcript mining planned header invalid"))?;
        ensure!(
            header.wal_format_version == EventHeaderV2::WAL_FORMAT_VERSION,
            "transcript mining planned wire version"
        );
        ensure!(
            header.event_schema_version == EventHeaderV2::EVENT_SCHEMA_VERSION,
            "transcript mining planned schema version"
        );
        ensure!(
            header.reserved_len == 0 && header.to_le_bytes() == bytes,
            "transcript mining planned header canonicality"
        );
        ensure!(
            header.payload_len as usize == payload.len(),
            "transcript mining planned payload length"
        );
        ensure!(
            header.total_len as usize
                == super::header::PREAMBLE_LEN
                    + HEADER_BODY_LEN
                    + payload.len()
                    + super::header::CRC_LEN,
            "transcript mining planned total length"
        );
        ensure!(
            header.payload_hash == xxhash_rust::xxh3::xxh3_64(&payload),
            "transcript mining planned payload hash"
        );
        let encoded = encode_frame(&header, &payload);
        let decoded = super::frame::decode_frame(&encoded)
            .map_err(|_| anyhow::anyhow!("transcript mining planned frame invalid"))?;
        ensure!(
            decoded.header == header && decoded.payload == payload.as_slice(),
            "transcript mining planned frame mismatch"
        );
        ensure!(
            payload.len() <= super::writer::MAX_PAYLOAD_BYTES,
            "transcript mining payload too large"
        );
        Ok(Self {
            header,
            header_bytes: bytes,
            header_sha256,
            payload,
            payload_sha256,
        })
    }

    fn receipt_for(
        &self,
        location: &super::scan::HomeWalFrameLocation,
        header: &EventHeaderV2,
        payload: &[u8],
    ) -> TranscriptMiningFrameReceipt {
        let bytes = encode_frame(header, payload);
        let frame_sha256: [u8; 32] = Sha256::digest(bytes).into();
        TranscriptMiningFrameReceipt {
            header_sha256: self.header_sha256,
            frame_sha256,
            payload_sha256: self.payload_sha256,
            location_sha256: location_sha256(location, &self.header_sha256, &frame_sha256),
        }
    }

    fn same_locator(&self, other: &EventHeaderV2) -> bool {
        self.header.event_id == other.event_id && self.header.hlc == other.hlc
    }
}

/// Stable, metadata-only digest of the physical authenticated location. The
/// raw segment name/offset is intentionally not exposed through the receipt.
fn location_sha256(
    location: &super::scan::HomeWalFrameLocation,
    header_sha256: &[u8; 32],
    frame_sha256: &[u8; 32],
) -> [u8; 32] {
    let name = location.segment_name.to_string_lossy();
    let mut digest = Sha256::new();
    digest.update(b"neoth/transcript-mining-location/v1\0");
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.update(location.segment_generation.to_be_bytes());
    digest.update(location.segment_seq.to_be_bytes());
    digest.update(location.segment_start_ts_ns.to_be_bytes());
    digest.update(location.segment_node_id);
    digest.update(location.logical_offset.to_be_bytes());
    digest.update(header_sha256);
    digest.update(frame_sha256);
    digest.finalize().into()
}

/// A planned fresh `RAW_TEXT` frame. Its constructor accepts only the exact
/// header/payload bytes persisted by the transcript-mining prepare transaction.
#[derive(Clone)]
pub(crate) struct PlannedRawTextDescriptor(PersistedFrameDescriptor);

impl std::fmt::Debug for PlannedRawTextDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlannedRawTextDescriptor([redacted])")
    }
}

impl PlannedRawTextDescriptor {
    pub(crate) fn from_persisted(
        header_bytes: &[u8],
        header_sha256: [u8; 32],
        payload: Vec<u8>,
        payload_sha256: [u8; 32],
    ) -> Result<Self> {
        let descriptor = PersistedFrameDescriptor::from_persisted(
            header_bytes,
            header_sha256,
            payload,
            payload_sha256,
        )?;
        ensure!(
            descriptor.header.event_type == EVENT_TYPE_RAW_TEXT
                && descriptor.header.event_subtype == 0,
            "transcript mining raw descriptor event kind"
        );
        Ok(Self(descriptor))
    }

    /// The sealed RAW descriptor is the only transcript-recovery source for
    /// its header attribution.  This exposes no logical label or minting API;
    /// it lets the immediately derived Bound descriptor retain the exact
    /// session already authenticated in the persisted RAW header.
    pub(crate) const fn header_session_id(&self) -> crate::wal::SessionId {
        self.0.header.session_id
    }
}

/// A planned metadata-only `TranscriptMiningBound` or `TranscriptMiningRevoked`
/// frame. Canonical codec validation is deliberately performed here, before the
/// writer sees an appendable descriptor.
#[derive(Clone)]
pub(crate) struct PlannedMiningOutboxDescriptor(PersistedFrameDescriptor, Option<i64>);

impl std::fmt::Debug for PlannedMiningOutboxDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlannedMiningOutboxDescriptor([metadata-redacted])")
    }
}

impl PlannedMiningOutboxDescriptor {
    pub(crate) fn from_persisted(
        header_bytes: &[u8],
        header_sha256: [u8; 32],
        payload: Vec<u8>,
        payload_sha256: [u8; 32],
    ) -> Result<Self> {
        let descriptor = PersistedFrameDescriptor::from_persisted(
            header_bytes,
            header_sha256,
            payload,
            payload_sha256,
        )?;
        ensure!(
            descriptor.header.event_type == EVENT_TYPE_EXTENDED,
            "transcript mining outbox event type"
        );
        let expiry = match ExtendedSubtype::from_u8(descriptor.header.event_subtype) {
            Some(ExtendedSubtype::TranscriptMiningBound) => {
                let parsed =
                    crate::memory::transcript_mining_provenance::TranscriptMiningBoundV1::decode(
                        &descriptor.payload,
                    )?;
                ensure!(
                    parsed.encode()? == descriptor.payload,
                    "transcript mining bound payload noncanonical"
                );
                Some(parsed.expires_at_unix())
            }
            Some(ExtendedSubtype::TranscriptMiningRevoked) => {
                let parsed =
                    crate::memory::transcript_mining_provenance::TranscriptMiningRevokedV1::decode(
                        &descriptor.payload,
                    )?;
                ensure!(
                    parsed.encode()? == descriptor.payload,
                    "transcript mining revoked payload noncanonical"
                );
                None
            }
            _ => anyhow::bail!("transcript mining outbox subtype"),
        };
        Ok(Self(descriptor, expiry))
    }
}

#[derive(Clone)]
pub(crate) enum TranscriptMiningDescriptor {
    Raw(PlannedRawTextDescriptor),
    Outbox(PlannedMiningOutboxDescriptor),
}

impl std::fmt::Debug for TranscriptMiningDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw(_) => f.write_str("TranscriptMiningDescriptor::Raw([redacted])"),
            Self::Outbox(_) => {
                f.write_str("TranscriptMiningDescriptor::Outbox([metadata-redacted])")
            }
        }
    }
}

impl TranscriptMiningDescriptor {
    pub(crate) fn raw(value: PlannedRawTextDescriptor) -> Self {
        Self::Raw(value)
    }
    pub(crate) fn outbox(value: PlannedMiningOutboxDescriptor) -> Self {
        Self::Outbox(value)
    }
    fn inner(&self) -> &PersistedFrameDescriptor {
        match self {
            Self::Raw(value) => &value.0,
            Self::Outbox(value) => &value.0,
        }
    }
    pub(crate) fn header(&self) -> EventHeaderV2 {
        self.inner().header
    }
    pub(crate) fn payload(&self) -> Vec<u8> {
        self.inner().payload.clone()
    }
    pub(crate) fn expired_absent(
        &self,
        observed_at_unix: i64,
    ) -> Option<ExpiredMiningFrameReceipt> {
        let Self::Outbox(outbox) = self else {
            return None;
        };
        let expires_at_unix = outbox.1?;
        (observed_at_unix >= expires_at_unix).then(|| ExpiredMiningFrameReceipt {
            operation_descriptor_sha256: descriptor_sha256(
                outbox.0.header_sha256,
                outbox.0.payload_sha256,
            ),
            header_sha256: outbox.0.header_sha256,
            payload_sha256: outbox.0.payload_sha256,
            observed_at_unix,
        })
    }
}

pub(crate) fn descriptor_sha256(header_sha256: [u8; 32], payload_sha256: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"neoth/transcript-mining-operation/v1\0");
    digest.update(header_sha256);
    digest.update(payload_sha256);
    digest.finalize().into()
}

/// Read authenticated primary-WAL evidence only. Absence is deliberately
/// indeterminate: only the writer-owned once path may turn proven absence into
/// an append.
pub(crate) fn verify_exact_at_home(
    home: &Path,
    expected: &TranscriptMiningDescriptor,
) -> std::result::Result<TranscriptMiningFrameReceipt, TranscriptMiningOnceError> {
    let expected = expected.inner();
    let mut exact = None;
    let mut exact_count = 0usize;
    let mut conflict = false;
    let scan = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |location, frame| {
            let observed_header = frame.header.to_le_bytes();
            if observed_header == expected.header_bytes
                && frame.payload == expected.payload.as_slice()
            {
                exact_count = exact_count.saturating_add(1);
                if exact.is_none() {
                    exact = Some(expected.receipt_for(location, &frame.header, frame.payload));
                }
            } else if expected.same_locator(&frame.header) {
                conflict = true;
            }
            Ok(())
        },
    )
    .map_err(|_| TranscriptMiningOnceError::Indeterminate)?;
    if conflict {
        return Err(TranscriptMiningOnceError::Conflict);
    }
    if exact_count > 1 {
        return Err(TranscriptMiningOnceError::Duplicate);
    }
    if let Some(receipt) = exact {
        return Ok(receipt);
    }
    let _ = scan;
    Err(TranscriptMiningOnceError::Indeterminate)
}

pub(crate) enum Lookup {
    Exact(TranscriptMiningFrameReceipt),
    AbsentComplete,
    Conflict,
    Duplicate,
    Indeterminate,
}

pub(crate) fn lookup_exact_at_home(home: &Path, expected: &TranscriptMiningDescriptor) -> Lookup {
    let expected = expected.inner();
    let mut exact = None;
    let mut count = 0usize;
    let mut conflict = false;
    let Ok(scan) = super::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        super::scan::supported_home_scan_limits(),
        |location, frame| {
            let observed_header = frame.header.to_le_bytes();
            if observed_header == expected.header_bytes
                && frame.payload == expected.payload.as_slice()
            {
                count = count.saturating_add(1);
                if exact.is_none() {
                    exact = Some(expected.receipt_for(location, &frame.header, frame.payload));
                }
            } else if expected.same_locator(&frame.header) {
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

    fn raw_header(payload: &[u8]) -> EventHeaderV2 {
        crate::wal::HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, payload).build()
    }

    #[test]
    fn raw_descriptor_accepts_only_its_exact_persisted_header_and_payload() {
        let payload = b"operator transcript".to_vec();
        let header = raw_header(&payload);
        let header_bytes = header.to_le_bytes();
        let header_sha: [u8; 32] = Sha256::digest(header_bytes).into();
        let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &header_bytes,
                header_sha,
                payload.clone(),
                payload_sha,
            )
            .is_ok()
        );

        let mut wrong_header_sha = header_sha;
        wrong_header_sha[0] ^= 1;
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &header_bytes,
                wrong_header_sha,
                payload.clone(),
                payload_sha,
            )
            .is_err()
        );

        let mut wrong_payload_sha = payload_sha;
        wrong_payload_sha[0] ^= 1;
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &header_bytes,
                header_sha,
                payload,
                wrong_payload_sha,
            )
            .is_err()
        );
    }

    #[test]
    fn raw_descriptor_refuses_an_extended_or_nonzero_subtype_header() {
        let payload = b"operator transcript".to_vec();
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::TranscriptMiningBound as u8)
            .build();
        let header_bytes = header.to_le_bytes();
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &header_bytes,
                Sha256::digest(header_bytes).into(),
                payload.clone(),
                Sha256::digest(&payload).into(),
            )
            .is_err()
        );
    }

    #[test]
    fn raw_descriptor_rejects_invalid_header_fields_even_with_recomputed_header_sha() {
        let payload = b"operator transcript".to_vec();
        let header = raw_header(&payload);
        let mut bytes = header.to_le_bytes();
        // payload_hash starts at wire offset 85. It is not covered by the
        // caller-supplied SHA trust boundary: recomputing that SHA must still
        // fail because the header no longer describes this payload.
        bytes[85] ^= 1;
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &bytes,
                Sha256::digest(bytes).into(),
                payload.clone(),
                Sha256::digest(&payload).into(),
            )
            .is_err()
        );

        let mut reserved = header.to_le_bytes();
        reserved[93] = 1;
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &reserved,
                Sha256::digest(reserved).into(),
                payload.clone(),
                Sha256::digest(&payload).into(),
            )
            .is_err()
        );

        let mut total = header.to_le_bytes();
        total[9] ^= 1;
        assert!(
            PlannedRawTextDescriptor::from_persisted(
                &total,
                Sha256::digest(total).into(),
                payload,
                Sha256::digest(b"operator transcript").into(),
            )
            .is_err()
        );
    }
}
