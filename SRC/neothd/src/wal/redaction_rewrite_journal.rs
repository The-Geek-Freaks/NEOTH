//! Signed, crash-recoverable journal for one authenticated LEAF rewrite.
//!
//! This journal carries only fixed digest bindings and a single canonical WAL
//! basename. It never contains erased payload bytes, source text, offsets, or
//! an ambient path. The WAL receipt remains the delivery proof; this file only
//! makes the gap around an atomic segment replacement recoverable.

use std::ffi::OsStr;
use std::path::{Component, Path};

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::redaction_rewrite_receipts::{
    RedactionRewriteReceiptDescriptor, derive_home_binding_sha256,
};

const JOURNAL_FILE: &str = ".redaction-rewrite-journal.json";
const JOURNAL_VERSION: u8 = 1;
const MAX_JOURNAL_BYTES: usize = 8 * 1024;
const MAX_TARGET_BASENAME_BYTES: usize = 255;
const JOURNAL_LOCK_FILE: &str = ".redaction-rewrite-journal.lock";

/// The physically retained target image, supplied by the no-follow staging
/// owner after it has read the target through its already-bound capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TargetImage {
    pub sha256: [u8; 32],
    pub len: u64,
}

impl TargetImage {
    pub(crate) const fn new(sha256: [u8; 32], len: u64) -> Self {
        Self { sha256, len }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    Delivered,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewriteJournal {
    version: u8,
    phase: JournalPhase,
    target_basename: String,
    descriptor_b64: String,
    operation_digest_hex: String,
    old_target_sha256_hex: String,
    new_target_sha256_hex: String,
    old_target_len: u64,
    new_target_len: u64,
    affected_frame_count: u64,
    offset_summary_sha256_hex: String,
    signer_pubkey: String,
    receipt_proof_sha256_hex: Option<String>,
    signature: String,
}

/// Recovery result. `NewPublished` must be fed into the writer-owned exact
/// receipt bridge before `mark_delivered` is called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryDecision {
    OldUnchanged,
    NewPublished {
        descriptor: RedactionRewriteReceiptDescriptor,
    },
    Delivered {
        descriptor: RedactionRewriteReceiptDescriptor,
        receipt_proof_sha256: [u8; 32],
    },
    Conflict,
}

/// Retained exclusive authority for a complete prepare/publish/receipt/deliver
/// transaction. The lock is both cross-process and capability-relative.
pub(crate) struct RewriteJournalAuthority {
    wal: crate::skills::store::BoundDirectory,
    home_binding_sha256: [u8; 32],
    _lock: std::fs::File,
}

/// A self-authenticated pending journal. It is usable for crash recovery even
/// when the caller cannot reconstruct erased source material or old digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingRewriteJournal {
    pub target_basename: String,
    pub descriptor: RedactionRewriteReceiptDescriptor,
    pub delivered_receipt_proof_sha256: Option<[u8; 32]>,
}

fn actual_hex32(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid {field}"
    );
    let mut parsed = [0_u8; 32];
    for (index, slot) in parsed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("decode {field}"))?;
    }
    Ok(parsed)
}

fn operation_digest(descriptor: &RedactionRewriteReceiptDescriptor) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth/redaction-rewrite-operation/v1\0");
    digest.update(descriptor.operation_id());
    actual_hex32(digest.finalize().into())
}

fn validate_target_basename(target_basename: &str) -> Result<()> {
    anyhow::ensure!(
        !target_basename.is_empty() && target_basename.len() <= MAX_TARGET_BASENAME_BYTES,
        "invalid bounded redaction rewrite target basename"
    );
    anyhow::ensure!(
        Path::new(target_basename).components().collect::<Vec<_>>()
            == vec![Component::Normal(OsStr::new(target_basename))],
        "redaction rewrite target must be one canonical basename"
    );
    Ok(())
}

/// Bind a local target-header identity, derived by the staging owner from the
/// canonical basename plus immutable segment coordinates, to this journaled
/// descriptor before publish or recovery proceeds.
pub(crate) fn validate_target_identity(
    descriptor: &RedactionRewriteReceiptDescriptor,
    derived_target_identity_sha256: [u8; 32],
) -> Result<()> {
    anyhow::ensure!(
        descriptor.target_identity_sha256() == derived_target_identity_sha256,
        "redaction rewrite journal target identity differs from the bound target header"
    );
    Ok(())
}

fn validate_home_binding(
    descriptor: &RedactionRewriteReceiptDescriptor,
    home_binding_sha256: [u8; 32],
) -> Result<()> {
    anyhow::ensure!(
        descriptor.home_binding_sha256() == home_binding_sha256,
        "redaction rewrite journal descriptor is bound to another home"
    );
    Ok(())
}

impl RewriteJournal {
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = b"neoth/redaction-rewrite-journal/v1\0".to_vec();
        for value in [
            self.version.to_string(),
            match self.phase {
                JournalPhase::Prepared => "prepared".into(),
                JournalPhase::Delivered => "delivered".into(),
            },
            self.target_basename.clone(),
            self.descriptor_b64.clone(),
            self.operation_digest_hex.clone(),
            self.old_target_sha256_hex.clone(),
            self.new_target_sha256_hex.clone(),
            self.old_target_len.to_string(),
            self.new_target_len.to_string(),
            self.affected_frame_count.to_string(),
            self.offset_summary_sha256_hex.clone(),
            self.signer_pubkey.clone(),
            self.receipt_proof_sha256_hex.clone().unwrap_or_default(),
        ] {
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn descriptor(&self) -> Result<RedactionRewriteReceiptDescriptor> {
        let raw = STANDARD
            .decode(&self.descriptor_b64)
            .context("decode journal descriptor")?;
        anyhow::ensure!(raw.len() == 224, "invalid journal descriptor size");
        RedactionRewriteReceiptDescriptor::decode_canonical(&raw).map_err(anyhow::Error::from)
    }

    fn validate(
        &self,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<RedactionRewriteReceiptDescriptor> {
        anyhow::ensure!(
            self.version == JOURNAL_VERSION,
            "unsupported redaction rewrite journal version"
        );
        validate_target_basename(&self.target_basename)?;
        anyhow::ensure!(
            self.signer_pubkey == crate::wal::signing::pubkey_b64(key),
            "redaction rewrite journal signer does not match current WAL signing anchor"
        );
        crate::wal::signing::verify_b64(
            &self.signer_pubkey,
            &self.signature,
            &self.unsigned_bytes(),
        )
        .context("verify redaction rewrite journal signature")?;
        let descriptor = self.descriptor()?;
        anyhow::ensure!(
            self.operation_digest_hex == operation_digest(&descriptor),
            "redaction rewrite journal operation digest mismatch"
        );
        anyhow::ensure!(
            self.old_target_sha256_hex == actual_hex32(descriptor.old_target_sha256())
                && self.new_target_sha256_hex == actual_hex32(descriptor.new_target_sha256()),
            "redaction rewrite journal target digest mismatch"
        );
        anyhow::ensure!(
            self.old_target_len == descriptor.old_target_len()
                && self.new_target_len == descriptor.new_target_len(),
            "redaction rewrite journal target length mismatch"
        );
        anyhow::ensure!(
            self.affected_frame_count == descriptor.affected_frame_count()
                && self.offset_summary_sha256_hex
                    == actual_hex32(descriptor.offset_summary_sha256()),
            "redaction rewrite journal rewrite summary mismatch"
        );
        match self.phase {
            JournalPhase::Prepared => anyhow::ensure!(
                self.receipt_proof_sha256_hex.is_none(),
                "prepared redaction rewrite journal cannot claim delivery"
            ),
            JournalPhase::Delivered => {
                let _ = parse_hex32(
                    self.receipt_proof_sha256_hex
                        .as_deref()
                        .context("delivered redaction rewrite journal lacks receipt proof")?,
                    "receipt proof digest",
                )?;
            }
        }
        Ok(descriptor)
    }
}

fn wal_dir(home: &Path) -> Result<crate::skills::store::BoundDirectory> {
    let anchor = home
        .parent()
        .context("redaction rewrite home has no trusted parent")?;
    crate::skills::store::open_bound_directory_from_trusted_anchor(
        anchor,
        &home.join("wal"),
        false,
        "redaction rewrite WAL directory",
    )?
    .context("redaction rewrite WAL directory is absent")
}

fn signing_key(wal: &crate::skills::store::BoundDirectory) -> Result<ed25519_dalek::SigningKey> {
    crate::wal::signing::load_existing_signing_key_with_recovery(
        &wal.display_path.join("signing.key"),
    )
    .context("load existing redaction rewrite signing anchor")
}

fn journal_path(wal: &crate::skills::store::BoundDirectory) -> std::path::PathBuf {
    wal.display_path.join(JOURNAL_FILE)
}

/// Acquire the one home-scoped lock before touching rewrite journal state.
pub(crate) fn acquire(home: &Path) -> Result<RewriteJournalAuthority> {
    let wal = wal_dir(home)?;
    let home_binding_sha256 = derive_home_binding_sha256(home)
        .context("derive canonical redaction rewrite home binding")?;
    let lock = super::redact::lock_segment_for_rewrite(&wal.display_path.join(JOURNAL_LOCK_FILE))
        .context("acquire redaction rewrite journal authority")?;
    Ok(RewriteJournalAuthority {
        wal,
        home_binding_sha256,
        _lock: lock,
    })
}

/// Load and verify one pending journal without requiring an externally rebuilt
/// descriptor. A malformed/unsigned/misanchored record fails closed.
pub(crate) fn load_pending(
    authority: &RewriteJournalAuthority,
) -> Result<Option<PendingRewriteJournal>> {
    let bytes = match crate::skills::store::read_regular_file_bounded(
        &authority.wal.dir,
        OsStr::new(JOURNAL_FILE),
        &journal_path(&authority.wal),
        MAX_JOURNAL_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error).context("read redaction rewrite journal"),
    };
    let journal: RewriteJournal =
        serde_json::from_slice(&bytes).context("parse redaction rewrite journal")?;
    let key = signing_key(&authority.wal)?;
    let descriptor = journal.validate(&key)?;
    validate_home_binding(&descriptor, authority.home_binding_sha256)?;
    let delivered_receipt_proof_sha256 = journal
        .receipt_proof_sha256_hex
        .as_deref()
        .map(|value| parse_hex32(value, "receipt proof digest"))
        .transpose()?;
    Ok(Some(PendingRewriteJournal {
        target_basename: journal.target_basename,
        descriptor,
        delivered_receipt_proof_sha256,
    }))
}

/// Persist signed intent before the irreversible target replacement.
pub(crate) fn prepare(
    authority: &RewriteJournalAuthority,
    target_basename: &str,
    expected: &RedactionRewriteReceiptDescriptor,
    derived_target_identity_sha256: [u8; 32],
    current: TargetImage,
) -> Result<()> {
    validate_target_basename(target_basename)?;
    validate_target_identity(expected, derived_target_identity_sha256)?;
    validate_home_binding(expected, authority.home_binding_sha256)?;
    anyhow::ensure!(
        current.sha256 == expected.old_target_sha256() && current.len == expected.old_target_len(),
        "redaction rewrite prepare target is not the descriptor old image"
    );
    if let Some(pending) = load_pending(authority)? {
        anyhow::ensure!(
            pending.target_basename == target_basename && pending.descriptor == *expected,
            "different pending redaction rewrite journal already owns this home"
        );
        anyhow::ensure!(
            pending.delivered_receipt_proof_sha256.is_none(),
            "pending redaction rewrite is already delivered"
        );
        return Ok(());
    }
    let key = signing_key(&authority.wal)?;
    let mut journal = RewriteJournal {
        version: JOURNAL_VERSION,
        phase: JournalPhase::Prepared,
        target_basename: target_basename.into(),
        descriptor_b64: STANDARD.encode(expected.encode()),
        operation_digest_hex: operation_digest(expected),
        old_target_sha256_hex: actual_hex32(expected.old_target_sha256()),
        new_target_sha256_hex: actual_hex32(expected.new_target_sha256()),
        old_target_len: expected.old_target_len(),
        new_target_len: expected.new_target_len(),
        affected_frame_count: expected.affected_frame_count(),
        offset_summary_sha256_hex: actual_hex32(expected.offset_summary_sha256()),
        signer_pubkey: crate::wal::signing::pubkey_b64(&key),
        receipt_proof_sha256_hex: None,
        signature: String::new(),
    };
    journal.signature = crate::wal::signing::sign_b64(&key, &journal.unsigned_bytes());
    let body = serde_json::to_vec(&journal).context("serialize redaction rewrite journal")?;
    anyhow::ensure!(
        body.len() <= MAX_JOURNAL_BYTES,
        "redaction rewrite journal exceeds bounded size"
    );
    crate::skills::store::atomic_write_private_child_create_new(
        &authority.wal.dir,
        OsStr::new(JOURNAL_FILE),
        &journal_path(&authority.wal),
        &body,
    )
    .context("durably create redaction rewrite journal")
}

/// Inspect a retained journal after a crash. Any unrecognised image is a
/// conflict and intentionally leaves the journal in place for operator repair.
pub(crate) fn recover(
    authority: &RewriteJournalAuthority,
    current: TargetImage,
) -> Result<Option<RecoveryDecision>> {
    let Some(pending) = load_pending(authority)? else {
        return Ok(None);
    };
    Ok(Some(classify_pending(&pending, current)))
}

fn classify_pending(pending: &PendingRewriteJournal, current: TargetImage) -> RecoveryDecision {
    let descriptor = pending.descriptor;
    if let Some(receipt_proof_sha256) = pending.delivered_receipt_proof_sha256 {
        return if current.sha256 == descriptor.new_target_sha256()
            && current.len == descriptor.new_target_len()
        {
            RecoveryDecision::Delivered {
                descriptor,
                receipt_proof_sha256,
            }
        } else {
            RecoveryDecision::Conflict
        };
    }
    if current.sha256 == descriptor.old_target_sha256()
        && current.len == descriptor.old_target_len()
    {
        RecoveryDecision::OldUnchanged
    } else if current.sha256 == descriptor.new_target_sha256()
        && current.len == descriptor.new_target_len()
    {
        RecoveryDecision::NewPublished { descriptor }
    } else {
        RecoveryDecision::Conflict
    }
}

/// Record the exact writer receipt proof only after authenticated append-once
/// readback succeeded. The Prepared journal is atomically replaced in place.
pub(crate) fn mark_delivered(
    authority: &RewriteJournalAuthority,
    expected: &RedactionRewriteReceiptDescriptor,
    receipt_proof_sha256: [u8; 32],
) -> Result<()> {
    let Some(pending) = load_pending(authority)? else {
        anyhow::bail!("redaction rewrite delivery has no prepared journal");
    };
    anyhow::ensure!(
        pending.descriptor == *expected && pending.delivered_receipt_proof_sha256.is_none(),
        "redaction rewrite delivery differs from saved prepared binding"
    );
    let bytes = crate::skills::store::read_regular_file_bounded(
        &authority.wal.dir,
        OsStr::new(JOURNAL_FILE),
        &journal_path(&authority.wal),
        MAX_JOURNAL_BYTES,
    )?;
    let mut journal: RewriteJournal =
        serde_json::from_slice(&bytes).context("parse prepared redaction rewrite journal")?;
    let key = signing_key(&authority.wal)?;
    let rebound = journal.validate(&key)?;
    validate_home_binding(&rebound, authority.home_binding_sha256)?;
    anyhow::ensure!(
        rebound == *expected,
        "redaction rewrite journal changed before delivery commit"
    );
    anyhow::ensure!(
        journal.phase == JournalPhase::Prepared,
        "redaction rewrite journal is already delivered"
    );
    journal.phase = JournalPhase::Delivered;
    journal.receipt_proof_sha256_hex = Some(actual_hex32(receipt_proof_sha256));
    journal.signature = crate::wal::signing::sign_b64(&key, &journal.unsigned_bytes());
    let body =
        serde_json::to_vec(&journal).context("serialize delivered redaction rewrite journal")?;
    anyhow::ensure!(
        body.len() <= MAX_JOURNAL_BYTES,
        "delivered redaction rewrite journal exceeds bounded size"
    );
    crate::skills::store::atomic_write_private_child(
        &authority.wal.dir,
        OsStr::new(JOURNAL_FILE),
        &journal_path(&authority.wal),
        &body,
    )
    .context("durably record redaction rewrite delivery")
}

/// Remove a Delivered journal only after the caller has re-bound the target
/// header identity, observed the exact new image, and independently confirmed
/// the same authenticated WAL receipt proof. This releases the single-home
/// journal namespace for a later rewrite without treating a signed intent as
/// delivery evidence.
pub(crate) fn finalize_delivered(
    authority: &RewriteJournalAuthority,
    expected: &RedactionRewriteReceiptDescriptor,
    derived_target_identity_sha256: [u8; 32],
    current: TargetImage,
    exact_receipt_proof_sha256: [u8; 32],
) -> Result<()> {
    validate_home_binding(expected, authority.home_binding_sha256)?;
    validate_target_identity(expected, derived_target_identity_sha256)?;
    anyhow::ensure!(
        current.sha256 == expected.new_target_sha256() && current.len == expected.new_target_len(),
        "redaction rewrite delivered target is not the descriptor new image"
    );
    let Some(pending) = load_pending(authority)? else {
        anyhow::bail!("redaction rewrite finalization has no delivered journal");
    };
    anyhow::ensure!(
        pending.descriptor == *expected,
        "redaction rewrite finalization differs from saved binding"
    );
    anyhow::ensure!(
        pending.delivered_receipt_proof_sha256 == Some(exact_receipt_proof_sha256),
        "redaction rewrite finalization receipt proof differs from saved delivery"
    );
    match recover(authority, current)? {
        Some(RecoveryDecision::Delivered {
            descriptor,
            receipt_proof_sha256,
        }) if descriptor == *expected && receipt_proof_sha256 == exact_receipt_proof_sha256 => {}
        _ => anyhow::bail!("redaction rewrite delivered journal is not safely finalizable"),
    }
    crate::skills::store::remove_child_file(
        &authority.wal.dir,
        OsStr::new(JOURNAL_FILE),
        &journal_path(&authority.wal),
    )
    .context("remove delivered redaction rewrite journal")?;
    crate::util::atomic_write::sync_parent_directory_required(&journal_path(&authority.wal))
        .context("durably finalize delivered redaction rewrite journal")
}

/// Discard only a prepared intent whose retained target is still exactly the
/// old image. A delivered or new image is never silently removed.
pub(crate) fn abandon_old_unchanged(
    authority: &RewriteJournalAuthority,
    current: TargetImage,
) -> Result<()> {
    match recover(authority, current)? {
        Some(RecoveryDecision::OldUnchanged) => {
            crate::skills::store::remove_child_file(
                &authority.wal.dir,
                OsStr::new(JOURNAL_FILE),
                &journal_path(&authority.wal),
            )
            .context("remove unchanged redaction rewrite journal")?;
            crate::util::atomic_write::sync_parent_directory_required(&journal_path(&authority.wal))
                .context("durably abandon unchanged redaction rewrite journal")
        }
        Some(_) => {
            anyhow::bail!("redaction rewrite journal may describe a published or delivered effect")
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(home: &Path) -> RedactionRewriteReceiptDescriptor {
        RedactionRewriteReceiptDescriptor::new(
            [1; 32],
            derive_home_binding_sha256(home).unwrap(),
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            7,
            80,
            72,
        )
        .unwrap()
    }

    #[test]
    fn signed_codec_rejects_tamper_and_wrong_target() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let expected = RedactionRewriteReceiptDescriptor::new(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 7, 80, 72,
        )
        .unwrap();
        let mut journal = RewriteJournal {
            version: JOURNAL_VERSION,
            phase: JournalPhase::Prepared,
            target_basename: "leaf-000001.wal".into(),
            descriptor_b64: STANDARD.encode(expected.encode()),
            operation_digest_hex: operation_digest(&expected),
            old_target_sha256_hex: actual_hex32(expected.old_target_sha256()),
            new_target_sha256_hex: actual_hex32(expected.new_target_sha256()),
            old_target_len: 80,
            new_target_len: 72,
            affected_frame_count: 7,
            offset_summary_sha256_hex: actual_hex32(expected.offset_summary_sha256()),
            signer_pubkey: crate::wal::signing::pubkey_b64(&key),
            receipt_proof_sha256_hex: None,
            signature: String::new(),
        };
        journal.signature = crate::wal::signing::sign_b64(&key, &journal.unsigned_bytes());
        assert!(journal.validate(&key).is_ok());
        journal.new_target_len = 73;
        assert!(journal.validate(&key).is_err());
    }

    #[test]
    fn target_basename_rejects_paths_and_empty_names() {
        assert!(validate_target_basename("leaf-000001.wal").is_ok());
        assert!(validate_target_basename("../leaf.wal").is_err());
        assert!(validate_target_basename("wal/leaf.wal").is_err());
        assert!(validate_target_basename("").is_err());
    }

    #[test]
    fn retained_images_classify_old_new_and_conflict_without_payload() {
        let descriptor = RedactionRewriteReceiptDescriptor::new(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 7, 80, 72,
        )
        .unwrap();
        let pending = PendingRewriteJournal {
            target_basename: "leaf-000001.wal".into(),
            descriptor,
            delivered_receipt_proof_sha256: None,
        };
        assert_eq!(
            classify_pending(&pending, TargetImage::new([4; 32], 80)),
            RecoveryDecision::OldUnchanged
        );
        assert_eq!(
            classify_pending(&pending, TargetImage::new([5; 32], 72)),
            RecoveryDecision::NewPublished { descriptor }
        );
        assert_eq!(
            classify_pending(&pending, TargetImage::new([8; 32], 72)),
            RecoveryDecision::Conflict
        );
    }

    #[test]
    fn private_atomic_journal_transitions_missing_prepared_delivered_and_old_abandon() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        crate::wal::signing::load_or_init_signing_key(&wal.join("signing.key")).unwrap();
        let expected = descriptor(home.path());
        let authority = acquire(home.path()).unwrap();
        assert!(load_pending(&authority).unwrap().is_none());
        prepare(
            &authority,
            "leaf-000001.wal",
            &expected,
            [3; 32],
            TargetImage::new([4; 32], 80),
        )
        .unwrap();
        assert_eq!(
            recover(&authority, TargetImage::new([4; 32], 80)).unwrap(),
            Some(RecoveryDecision::OldUnchanged)
        );
        assert_eq!(
            recover(&authority, TargetImage::new([5; 32], 72)).unwrap(),
            Some(RecoveryDecision::NewPublished {
                descriptor: expected
            })
        );
        mark_delivered(&authority, &expected, [9; 32]).unwrap();
        assert_eq!(
            recover(&authority, TargetImage::new([5; 32], 72)).unwrap(),
            Some(RecoveryDecision::Delivered {
                descriptor: expected,
                receipt_proof_sha256: [9; 32]
            })
        );
        assert_eq!(
            recover(&authority, TargetImage::new([4; 32], 80)).unwrap(),
            Some(RecoveryDecision::Conflict)
        );
        assert_eq!(
            recover(&authority, TargetImage::new([8; 32], 72)).unwrap(),
            Some(RecoveryDecision::Conflict)
        );
        assert!(
            finalize_delivered(
                &authority,
                &expected,
                [3; 32],
                TargetImage::new([4; 32], 80),
                [9; 32]
            )
            .is_err()
        );
        finalize_delivered(
            &authority,
            &expected,
            [3; 32],
            TargetImage::new([5; 32], 72),
            [9; 32],
        )
        .unwrap();
        assert!(load_pending(&authority).unwrap().is_none());
        let next = RedactionRewriteReceiptDescriptor::new(
            [10; 32],
            derive_home_binding_sha256(home.path()).unwrap(),
            [3; 32],
            [5; 32],
            [7; 32],
            [11; 32],
            1,
            72,
            64,
        )
        .unwrap();
        prepare(
            &authority,
            "leaf-000001.wal",
            &next,
            [3; 32],
            TargetImage::new([5; 32], 72),
        )
        .unwrap();

        let other = tempfile::tempdir().unwrap();
        let other_wal = other.path().join("wal");
        std::fs::create_dir(&other_wal).unwrap();
        crate::wal::signing::load_or_init_signing_key(&other_wal.join("signing.key")).unwrap();
        let other_expected = descriptor(other.path());
        let other_authority = acquire(other.path()).unwrap();
        assert!(
            prepare(
                &other_authority,
                "leaf-000002.wal",
                &expected,
                [3; 32],
                TargetImage::new([4; 32], 80)
            )
            .is_err()
        );
        assert!(
            prepare(
                &other_authority,
                "leaf-000002.wal",
                &other_expected,
                [8; 32],
                TargetImage::new([4; 32], 80)
            )
            .is_err()
        );
        prepare(
            &other_authority,
            "leaf-000002.wal",
            &other_expected,
            [3; 32],
            TargetImage::new([4; 32], 80),
        )
        .unwrap();
        abandon_old_unchanged(&other_authority, TargetImage::new([4; 32], 80)).unwrap();
        assert!(load_pending(&other_authority).unwrap().is_none());
    }
}
