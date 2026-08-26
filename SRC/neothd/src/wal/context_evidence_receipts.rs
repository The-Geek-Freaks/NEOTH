//! Bounded, authenticated append-once evidence for Context Connector receipts.
//!
//! The receipt is deliberately *not* looked up by scanning the primary WAL.
//! That was safe only while a home was tiny: a mature but valid home could
//! force an acknowledgement to retain several GiB of logical segments.  This
//! ledger is the canonical durable evidence instead.  It has a fixed lifetime
//! capacity, fixed-size shard records, and a bounded transaction protocol.
//!
//! Files live below `<home>/wal/context-evidence-receipts`.  Every namespace
//! operation is relative to a capability-bound directory.  The stable private
//! `ledger.key` is independent from the rotating WAL HMAC key: losing it after
//! any ledger evidence exists is intentionally fatal, rather than silently
//! treating durable receipts as absent.
//!
//! A generation-named authenticated anchor is retained directly under `wal/`
//! and removed for the predecessor only after its successor is anchored.  It
//! detects selective replacement of the ledger directory or `ledger.key` while
//! the surrounding WAL namespace remains intact.  It cannot detect an attacker
//! who can restore a complete coordinated snapshot of both namespaces; that
//! requires an OS- or remote-monotonic storage primitive and is deliberately
//! not claimed as a cryptographic guarantee here.

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

use crate::skills::store;
use crate::wal::events::{ContextEvidenceReceipt, EVENT_TYPE_EXTENDED, ExtendedSubtype};

const LEDGER_DIR: &str = "context-evidence-receipts";
const ANCHOR_DIR: &str = "context-evidence-receipt-anchors";
const LEDGER_KEY: &str = "ledger.key";
const PENDING: &str = "pending.v1";
const ANCHOR_PREFIX: &str = "context-evidence-receipts.anchor-";

const SHARD_COUNT: usize = 256;
const RECORDS_PER_SHARD: usize = 4096;
const LIFETIME_CAPACITY: usize = SHARD_COUNT * RECORDS_PER_SHARD;

const FRAME_MAX_BYTES: usize = 360;
const RECORD_BYTES: usize = 368; // u16 len + six reserved + fixed frame area
const RECORDS_BYTES: usize = RECORDS_PER_SHARD * RECORD_BYTES;

const SHARD_MAGIC: &[u8; 8] = b"NTHCER01";
const MANIFEST_MAGIC: &[u8; 8] = b"NTHCEM01";
const PENDING_MAGIC: &[u8; 8] = b"NTHCEP01";
const ANCHOR_MAGIC: &[u8; 8] = b"NTHCEA01";
const FORMAT_VERSION: u16 = 1;
const TAG_BYTES: usize = 32;
const SHA_BYTES: usize = 32;
const SHARD_HEADER_BYTES: usize = 56;
const SHARD_BYTES: usize = SHARD_HEADER_BYTES + RECORDS_BYTES + TAG_BYTES;
const MANIFEST_HEADER_BYTES: usize = 68;
const MANIFEST_ENTRY_BYTES: usize = 44;
const MANIFEST_BYTES: usize =
    MANIFEST_HEADER_BYTES + SHARD_COUNT * MANIFEST_ENTRY_BYTES + TAG_BYTES;
const PENDING_PREFIX_BYTES: usize = 128;
const PENDING_BYTES: usize = PENDING_PREFIX_BYTES + MANIFEST_BYTES + TAG_BYTES;
const ANCHOR_BYTES: usize = 116;

/// Strict independent ceilings for one receipt operation.  These are not
/// estimates: normal admission reads one manifest and one shard, then writes
/// one pending journal, one inactive-slot shard, and one manifest.
pub(crate) const MAX_DIRECTORY_ENTRIES: usize = 1024;
pub(crate) const MAX_OPERATION_DIRECTORY_ENTRIES: usize = MAX_DIRECTORY_ENTRIES * 6;
pub(crate) const MAX_OPERATION_FILE_READS: usize = 14;
pub(crate) const MAX_OPERATION_READ_BYTES: usize =
    MANIFEST_BYTES * 4 + SHARD_BYTES * 4 + PENDING_BYTES;
// Recovery may have to publish the manifest + anchor of one authenticated
// pending predecessor before the requested handle can start its own complete
// transaction.  Admission covers both bounded phases, including first-key
// initialization, before either phase is allowed to extend a file.
pub(crate) const MAX_TRANSACTION_BYTES: u64 = (MAX_LEDGER_KEY_FILE_BYTES
    + PENDING_BYTES
    + SHARD_BYTES
    + MANIFEST_BYTES * 2
    + ANCHOR_BYTES * 2) as u64;

const MAX_LEDGER_KEY_FILE_BYTES: usize = 512;
const MAX_RECOVERY_ORPHANS: usize = 2;
const MAX_ACCOUNTED_OBJECTS: usize = 8;
const ZERO_SHA: [u8; SHA_BYTES] = [0; SHA_BYTES];
const DOMAIN_FILE: &[u8] = b"neoth.context-evidence-receipts.file.v1\0";
const DOMAIN_SHARD: &[u8] = b"neoth.context-evidence-receipts.shard.v1\0";
const DOMAIN_ANCHOR: &[u8] = b"neoth.context-evidence-receipts.anchor.v1\0";

/// Ledger v1 is the first emitting format for subtype `0x27`.  The baseline
/// codec was deliberately reserved but un-wired.  If an explicit offline
/// forensic audit nevertheless discovers a historical primary-WAL `0x27`, it
/// is migration evidence: runtime admission must fail closed and must never
/// treat the new ledger's authenticated absence as proof of absence there.
pub(crate) const LEDGER_V1_IS_FIRST_CONTEXT_EVIDENCE_RECEIPT_PRODUCER: bool = true;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestCanonicalObject {
    Key,
    Pending,
    Shard,
    Manifest,
    Anchor,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestCanonicalWriteFailure {
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    AfterParentSync,
    RollbackRemove,
    RollbackParentSync,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestTransactionFailure {
    AfterKey,
    AfterPending,
    AfterShard,
    AfterManifest,
    AfterAnchor,
    AfterPendingRemoval,
}

#[cfg(test)]
static TEST_CANONICAL_WRITE_FAILURES: std::sync::Mutex<
    Vec<(
        std::path::PathBuf,
        TestCanonicalObject,
        TestCanonicalWriteFailure,
    )>,
> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static TEST_TRANSACTION_FAILURES: std::sync::Mutex<
    Vec<(std::path::PathBuf, TestTransactionFailure)>,
> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn fail_canonical_write_for_test(
    parent: &Path,
    object: TestCanonicalObject,
    failure: TestCanonicalWriteFailure,
) {
    let mut failures = TEST_CANONICAL_WRITE_FAILURES
        .lock()
        .expect("receipt canonical-write test hook poisoned");
    failures.retain(|(candidate_parent, candidate_object, candidate_failure)| {
        candidate_parent != parent || *candidate_object != object || *candidate_failure != failure
    });
    failures.push((parent.to_path_buf(), object, failure));
}

#[cfg(test)]
pub(crate) fn fail_transaction_after_for_test(home: &Path, failure: TestTransactionFailure) {
    let mut failures = TEST_TRANSACTION_FAILURES
        .lock()
        .expect("receipt transaction test hook poisoned");
    failures.retain(|(candidate, candidate_failure)| {
        candidate != home || *candidate_failure != failure
    });
    failures.push((home.to_path_buf(), failure));
}

#[cfg(test)]
fn canonical_object_for_test(namespace: ObjectNamespace, name: &str) -> TestCanonicalObject {
    match (namespace, name) {
        (ObjectNamespace::Anchor, _) => TestCanonicalObject::Anchor,
        (ObjectNamespace::Ledger, LEDGER_KEY) => TestCanonicalObject::Key,
        (ObjectNamespace::Ledger, PENDING) => TestCanonicalObject::Pending,
        (ObjectNamespace::Ledger, candidate) if parse_shard_name(candidate).is_some() => {
            TestCanonicalObject::Shard
        }
        (ObjectNamespace::Ledger, _) => TestCanonicalObject::Manifest,
    }
}

#[cfg(test)]
fn inject_canonical_write_failure(
    parent: &Path,
    object: TestCanonicalObject,
    failure: TestCanonicalWriteFailure,
) -> Result<()> {
    let mut failures = TEST_CANONICAL_WRITE_FAILURES
        .lock()
        .expect("receipt canonical-write test hook poisoned");
    if let Some(index) =
        failures
            .iter()
            .position(|(candidate_parent, candidate_object, candidate_failure)| {
                candidate_parent == parent
                    && *candidate_object == object
                    && *candidate_failure == failure
            })
    {
        failures.swap_remove(index);
        anyhow::bail!("injected receipt canonical-write failure at {failure:?}");
    }
    Ok(())
}

#[cfg(test)]
fn inject_transaction_failure(
    ledger: &store::BoundDirectory,
    failure: TestTransactionFailure,
) -> Result<()> {
    let wal = ledger
        .display_path
        .parent()
        .context("receipt ledger has no WAL parent for test hook")?;
    let home = wal
        .parent()
        .context("receipt WAL has no home parent for test hook")?;
    let mut failures = TEST_TRANSACTION_FAILURES
        .lock()
        .expect("receipt transaction test hook poisoned");
    if let Some(index) = failures.iter().position(|(candidate, candidate_failure)| {
        candidate == home && *candidate_failure == failure
    }) {
        failures.swap_remove(index);
        anyhow::bail!("injected receipt transaction failure at {failure:?}");
    }
    Ok(())
}

/// Result of a closed receipt decision.  It intentionally carries no handle,
/// source, path, account, or content-derived value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppendDecision {
    Appended,
    AlreadyPresent,
}

/// Exact durable delta after a successful append decision.  A duplicate has
/// zero delta; an existing shard replacement also nets to zero once its prior
/// generation is capability-bound and removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AppendOutcome {
    decision: AppendDecision,
    retained_bytes: u64,
    reclaimed_bytes: u64,
    replacement_bytes: u64,
    reclaimed_debt_bytes: u64,
}

impl AppendOutcome {
    #[must_use]
    pub(crate) const fn decision(&self) -> AppendDecision {
        self.decision
    }

    #[must_use]
    pub(crate) const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Bytes from a prior indeterminate receipt transaction that this
    /// authenticated operation capability-bound, removed, and parent-synced.
    /// The writer releases at most its in-memory receipt debt, never an
    /// unrelated quota reservation.
    #[must_use]
    pub(crate) const fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_bytes
    }

    /// Portion of the success-path retained objects that replaced exact
    /// pre-existing objects.  The writer uses this only to transfer a still
    /// live receipt-debt reservation; it is never extra physical growth.
    #[must_use]
    pub(crate) const fn replacement_bytes(&self) -> u64 {
        self.replacement_bytes
    }

    /// Exact still-unmeasured receipt-debt bytes whose capability-bound
    /// objects were removed and whose parent directories were synced.
    #[must_use]
    pub(crate) const fn reclaimed_debt_bytes(&self) -> u64 {
        self.reclaimed_debt_bytes
    }
}

/// Internal failure accounting.  The writer maps `cause` to its stable
/// content-free public error while retaining this conservative physical bound
/// in quota RAII until a subsequent authenticated recovery frees it.
#[derive(Debug)]
pub(crate) struct AppendFailure {
    retained_bytes: u64,
    reclaimed_bytes: u64,
    reclaimed_debt_bytes: u64,
    cause: anyhow::Error,
}

impl AppendFailure {
    #[must_use]
    pub(crate) const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    #[must_use]
    pub(crate) const fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_bytes
    }

    #[must_use]
    pub(crate) const fn reclaimed_debt_bytes(&self) -> u64 {
        self.reclaimed_debt_bytes
    }
}

impl std::fmt::Display for AppendFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

impl std::error::Error for AppendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.root_cause())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectNamespace {
    Ledger,
    Anchor,
}

#[derive(Clone, Debug)]
struct AccountedObject {
    namespace: ObjectNamespace,
    name: String,
    bytes: u64,
}

#[derive(Debug)]
struct DebtObject {
    object: AccountedObject,
    /// Portion backed by a receipt-specific, still-unmeasured reservation.
    owned_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DebtReclaim {
    /// Reservation charge that exact cleanup may release. This can exceed the
    /// observed file length when an earlier publication was indeterminate.
    owned_bytes: u64,
    /// Conservative replacement credit still funded by an older ordinary
    /// object. It never exceeds the bytes observed on the removed object.
    inherited_bytes: u64,
    /// Exact file lengths removed for separating debt from ordinary cleanup.
    removed_bytes: u64,
}

/// Bounded writer-lifetime ownership for indeterminate receipt mutations.
///
/// Object identity stays private to this module.  The writer receives only the
/// exact aggregate it may release after a capability-bound unlink and parent
/// sync.  `inherited_bytes` records replacement capacity already funded by an
/// older ordinary object, so a retry neither double-charges it nor releases an
/// unrelated reservation.
#[derive(Debug, Default)]
pub(crate) struct ReceiptQuotaDebt {
    objects: Vec<DebtObject>,
}

impl ReceiptQuotaDebt {
    fn reconcile_removals(&mut self, removed: &[AccountedObject]) -> Result<DebtReclaim> {
        let mut matches = Vec::new();
        let mut reclaim = DebtReclaim::default();
        for removed_object in removed {
            let Some(index) = self.objects.iter().position(|debt| {
                debt.object.namespace == removed_object.namespace
                    && debt.object.name == removed_object.name
            }) else {
                continue;
            };
            anyhow::ensure!(
                !matches.contains(&index),
                "receipt ledger debt object was removed twice"
            );
            let debt = &self.objects[index];
            anyhow::ensure!(
                removed_object.bytes <= debt.object.bytes,
                "receipt ledger removal exceeded its exact retained-debt bound"
            );
            reclaim.owned_bytes = reclaim
                .owned_bytes
                .checked_add(debt.owned_bytes)
                .context("receipt ledger owned-debt reclaim overflow")?;
            let inherited_bound = debt.object.bytes.saturating_sub(debt.owned_bytes);
            let inherited_observed = removed_object
                .bytes
                .saturating_sub(debt.owned_bytes)
                .min(inherited_bound);
            reclaim.inherited_bytes = reclaim
                .inherited_bytes
                .checked_add(inherited_observed)
                .context("receipt ledger inherited-debt reclaim overflow")?;
            reclaim.removed_bytes = reclaim
                .removed_bytes
                .checked_add(removed_object.bytes)
                .context("receipt ledger removed-debt accounting overflow")?;
            matches.push(index);
        }
        matches.sort_unstable();
        for index in matches.into_iter().rev() {
            self.objects.remove(index);
        }
        Ok(reclaim)
    }

    fn retain_failed_objects(
        &mut self,
        retained: &[AccountedObject],
        inherited_capacity: u64,
    ) -> Result<u64> {
        anyhow::ensure!(
            self.objects.len().saturating_add(retained.len()) <= MAX_ACCOUNTED_OBJECTS,
            "receipt ledger retained-debt object bound exceeded"
        );
        anyhow::ensure!(
            retained.iter().all(|candidate| {
                !self.objects.iter().any(|debt| {
                    debt.object.namespace == candidate.namespace
                        && debt.object.name == candidate.name
                })
            }),
            "receipt ledger retained-debt object was recorded twice"
        );
        let mut inherited_remaining = inherited_capacity;
        let mut newly_owned = 0u64;
        for object in retained {
            let inherited = object.bytes.min(inherited_remaining);
            inherited_remaining -= inherited;
            let owned_bytes = object.bytes.saturating_sub(inherited);
            newly_owned = newly_owned
                .checked_add(owned_bytes)
                .context("receipt ledger owned-debt accounting overflow")?;
            self.objects.push(DebtObject {
                object: object.clone(),
                owned_bytes,
            });
        }
        Ok(newly_owned)
    }
}

/// Per-invocation physical-delta ledger.  Every canonical object is charged at
/// its maximum before `create_new` can run.  A charge is reduced only after a
/// typed publication result proves the actual length, or removed only after an
/// exact-object delete and parent-directory sync both succeed.
#[derive(Default)]
struct MutationAccounting {
    newly_retained: Vec<AccountedObject>,
    reclaimed_preexisting: u64,
    removed_preexisting: Vec<AccountedObject>,
}

impl MutationAccounting {
    fn precharge(
        &mut self,
        namespace: ObjectNamespace,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<usize> {
        anyhow::ensure!(
            !self
                .newly_retained
                .iter()
                .any(|object| object.namespace == namespace && object.name == name),
            "receipt ledger object was charged twice in one operation"
        );
        let projected = self
            .retained_bytes()?
            .checked_add(maximum_bytes)
            .context("receipt ledger mutation accounting overflow")?;
        anyhow::ensure!(
            projected <= MAX_TRANSACTION_BYTES,
            "receipt ledger operation exceeded its admitted mutation bound"
        );
        anyhow::ensure!(
            self.newly_retained.len() < MAX_ACCOUNTED_OBJECTS,
            "receipt ledger mutation object bound exceeded"
        );
        self.newly_retained.push(AccountedObject {
            namespace,
            name: name.to_owned(),
            bytes: maximum_bytes,
        });
        Ok(self.newly_retained.len() - 1)
    }

    fn publication_length(&mut self, token: usize, actual_bytes: u64) -> Result<()> {
        let object = self
            .newly_retained
            .get_mut(token)
            .context("receipt ledger publication accounting token is invalid")?;
        anyhow::ensure!(
            actual_bytes <= object.bytes,
            "receipt ledger publication exceeded its precharged object maximum"
        );
        object.bytes = actual_bytes;
        Ok(())
    }

    fn rolled_back_durably(&mut self, token: usize) -> Result<()> {
        anyhow::ensure!(
            token + 1 == self.newly_retained.len(),
            "receipt ledger rollback accounting is not the active mutation"
        );
        self.newly_retained.pop();
        Ok(())
    }

    fn removed_durably(
        &mut self,
        namespace: ObjectNamespace,
        name: &str,
        removed_bytes: u64,
    ) -> Result<()> {
        if let Some(index) = self
            .newly_retained
            .iter()
            .position(|object| object.namespace == namespace && object.name == name)
        {
            let object = self.newly_retained.remove(index);
            anyhow::ensure!(
                removed_bytes <= object.bytes,
                "receipt ledger removed object exceeded its retained charge"
            );
            return Ok(());
        }
        self.reclaimed_preexisting = self
            .reclaimed_preexisting
            .checked_add(removed_bytes)
            .context("receipt ledger reclaimed-byte accounting overflow")?;
        anyhow::ensure!(
            self.removed_preexisting.len() < MAX_ACCOUNTED_OBJECTS,
            "receipt ledger removal object bound exceeded"
        );
        self.removed_preexisting.push(AccountedObject {
            namespace,
            name: name.to_owned(),
            bytes: removed_bytes,
        });
        Ok(())
    }

    fn retained_bytes(&self) -> Result<u64> {
        self.newly_retained.iter().try_fold(0u64, |total, object| {
            total
                .checked_add(object.bytes)
                .context("receipt ledger retained-byte accounting overflow")
        })
    }

    const fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_preexisting
    }

    fn success_outcome(
        &self,
        decision: AppendDecision,
        debt_reclaim: DebtReclaim,
    ) -> Result<AppendOutcome> {
        let newly_retained = self.retained_bytes()?;
        let reclaimed_bytes = self.reclaimed_bytes();
        let ordinary_reclaimed = reclaimed_bytes
            .checked_sub(debt_reclaim.removed_bytes)
            .context("receipt ledger debt reclaim exceeded durable removals")?;
        let replacement_bytes = newly_retained.min(
            ordinary_reclaimed
                .checked_add(debt_reclaim.inherited_bytes)
                .context("receipt ledger replacement accounting overflow")?,
        );
        Ok(AppendOutcome {
            decision,
            retained_bytes: newly_retained.saturating_sub(replacement_bytes),
            reclaimed_bytes,
            replacement_bytes,
            reclaimed_debt_bytes: debt_reclaim.owned_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestEntry {
    present: bool,
    slot: u8,
    count: u16,
    generation: u64,
    shard_sha256: [u8; SHA_BYTES],
}

impl ManifestEntry {
    const EMPTY: Self = Self {
        present: false,
        slot: 0,
        count: 0,
        generation: 0,
        shard_sha256: ZERO_SHA,
    };
}

struct Manifest {
    generation: u64,
    previous_generation: u64,
    previous_sha256: [u8; SHA_BYTES],
    total_records: u32,
    entries: [ManifestEntry; SHARD_COUNT],
    bytes: Vec<u8>,
}

struct Shard {
    shard: u8,
    slot: u8,
    generation: u64,
    count: usize,
    bytes: Vec<u8>,
    handles: Vec<[u8; 32]>,
}

struct Pending {
    old_manifest_sha256: [u8; SHA_BYTES],
    new_generation: u64,
    shard: u8,
    slot: u8,
    new_shard_sha256: [u8; SHA_BYTES],
    new_manifest_sha256: [u8; SHA_BYTES],
    manifest: Manifest,
}

#[derive(Default)]
struct IoBudget {
    entries: usize,
    files: usize,
    bytes: usize,
}

impl IoBudget {
    fn entry(&mut self) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("receipt ledger entry budget overflow")?;
        anyhow::ensure!(
            self.entries <= MAX_OPERATION_DIRECTORY_ENTRIES,
            "receipt ledger operation entry budget exceeded"
        );
        Ok(())
    }

    fn read(&mut self, bytes: usize) -> Result<()> {
        self.files = self
            .files
            .checked_add(1)
            .context("receipt ledger file-read budget overflow")?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("receipt ledger byte-read budget overflow")?;
        anyhow::ensure!(
            self.files <= MAX_OPERATION_FILE_READS,
            "receipt ledger file-read budget exceeded"
        );
        anyhow::ensure!(
            self.bytes <= MAX_OPERATION_READ_BYTES,
            "receipt ledger byte-read budget exceeded"
        );
        Ok(())
    }
}

/// Append exact authenticated receipt evidence at most once.  The caller must
/// retain the writer's process + cross-process receipt authority for this
/// complete call; this module adds no unbounded process cache or WAL scan.
pub(crate) fn append_once(
    home: &Path,
    handle: &[u8; 32],
    expected: &ContextEvidenceReceipt,
    exact_frame: &[u8],
) -> std::result::Result<AppendOutcome, AppendFailure> {
    append_once_with_quota_debt(
        home,
        handle,
        expected,
        exact_frame,
        &mut ReceiptQuotaDebt::default(),
    )
}

/// Production entry point.  `quota_debt` must live for the complete writer
/// lifetime so only a later exact-object recovery can release bytes retained by
/// an indeterminate earlier call.
pub(crate) fn append_once_with_quota_debt(
    home: &Path,
    handle: &[u8; 32],
    expected: &ContextEvidenceReceipt,
    exact_frame: &[u8],
    quota_debt: &mut ReceiptQuotaDebt,
) -> std::result::Result<AppendOutcome, AppendFailure> {
    let mut accounting = MutationAccounting::default();
    let result = (|| -> Result<AppendDecision> {
        validate_exact_frame(handle, expected, exact_frame)?;
        let mut budget = IoBudget::default();
        let ledger = open_ledger_directory(home)?;
        let mut entries = list_entries(&ledger.dir, &ledger.display_path, &mut budget)?;
        recover_windows_empty_stages(&ledger, &entries, &mut budget)?;
        entries = list_entries(&ledger.dir, &ledger.display_path, &mut budget)?;
        validate_names(&entries)?;
        let key = load_or_initialize_key(&ledger, &entries, &mut budget, &mut accounting)?;

        let mut state = recover_state(&ledger, &key, &mut budget, &mut accounting)?;
        let prior_generation = state.as_ref().map(|manifest| manifest.generation);
        let shard_index = shard_for_handle(&key, handle) as usize;

        let active_entry = state
            .as_ref()
            .map(|manifest| manifest.entries[shard_index])
            .unwrap_or(ManifestEntry::EMPTY);
        let active_generation = state.as_ref().map_or(0, |manifest| manifest.generation);
        let mut shard = if active_entry.present {
            read_shard_for_entry(&ledger, shard_index as u8, active_entry, &key, &mut budget)?
        } else {
            empty_shard(
                shard_index as u8,
                active_generation
                    .checked_add(1)
                    .context("receipt ledger generation overflow")?,
            )
        };

        let old_total = state
            .as_ref()
            .map_or(0u32, |manifest| manifest.total_records);
        match shard.handles.binary_search(handle) {
            Ok(position) => {
                let stored = receipt_at(&shard, position)?;
                anyhow::ensure!(
                    stored == *expected,
                    "receipt ledger handle payload collision"
                );
                return Ok(AppendDecision::AlreadyPresent);
            }
            Err(position) => {
                // Both the global and selected-shard caps are checked before the
                // in-memory record move, never after a persistable state changes.
                ensure_insert_capacity(old_total, shard.count)?;
                insert_record(&mut shard, position, handle, exact_frame)?;
            }
        }

        let next_generation = active_generation
            .checked_add(1)
            .context("receipt ledger generation overflow")?;
        let new_slot = if active_entry.present {
            active_entry.slot ^ 1
        } else {
            0
        };
        shard.generation = next_generation;
        shard.slot = new_slot;
        finalize_shard(&mut shard, &key)?;
        let shard_sha = sha256(&shard.bytes);

        let old_manifest_sha = state
            .as_ref()
            .map_or(ZERO_SHA, |manifest| sha256(&manifest.bytes));
        let mut new_manifest = next_manifest(
            state.as_ref(),
            next_generation,
            shard_index,
            new_slot,
            shard.count,
            shard_sha,
        )?;
        finalize_manifest(&mut new_manifest, &key)?;
        let pending = Pending {
            old_manifest_sha256: old_manifest_sha,
            new_generation: next_generation,
            shard: shard_index as u8,
            slot: new_slot,
            new_shard_sha256: shard_sha,
            new_manifest_sha256: sha256(&new_manifest.bytes),
            manifest: new_manifest,
        };

        write_transaction(&ledger, &key, &pending, &shard, &mut accounting)?;
        publish_anchor(
            &ledger,
            &key,
            &pending.manifest,
            &mut budget,
            &mut accounting,
        )?;
        remove_pending_accounted(&ledger, &mut accounting)?;
        // Re-open only after a fully committed transaction; the local binding is
        // intentionally not retained in an unbounded cache.
        state = Some(pending.manifest);
        cleanup_after_commit(
            &ledger,
            &key,
            state.as_ref().expect("just committed manifest"),
            &mut budget,
            &mut accounting,
        )?;
        if let Some(generation) = prior_generation {
            remove_anchor(&ledger, generation, &mut accounting)?;
        }
        Ok(AppendDecision::Appended)
    })();
    let debt_reclaim = match quota_debt.reconcile_removals(&accounting.removed_preexisting) {
        Ok(reclaim) => reclaim,
        Err(cause) => {
            return Err(AppendFailure {
                retained_bytes: MAX_TRANSACTION_BYTES,
                reclaimed_bytes: accounting.reclaimed_bytes(),
                reclaimed_debt_bytes: 0,
                cause,
            });
        }
    };
    match result {
        Ok(decision) => accounting
            .success_outcome(decision, debt_reclaim)
            .map_err(|cause| AppendFailure {
                retained_bytes: MAX_TRANSACTION_BYTES,
                reclaimed_bytes: accounting.reclaimed_bytes(),
                reclaimed_debt_bytes: debt_reclaim.owned_bytes,
                cause,
            }),
        Err(mut cause) => {
            let ordinary_reclaimed = accounting
                .reclaimed_bytes()
                .checked_sub(debt_reclaim.removed_bytes)
                .unwrap_or(0);
            let inherited_capacity = ordinary_reclaimed
                .checked_add(debt_reclaim.inherited_bytes)
                .unwrap_or(MAX_TRANSACTION_BYTES);
            let retained_bytes = match quota_debt
                .retain_failed_objects(&accounting.newly_retained, inherited_capacity)
            {
                Ok(bytes) => bytes,
                Err(accounting_error) => {
                    cause = cause.context(format!(
                        "receipt ledger retained-debt accounting failed: {accounting_error:#}"
                    ));
                    MAX_TRANSACTION_BYTES
                }
            };
            Err(AppendFailure {
                retained_bytes,
                reclaimed_bytes: accounting.reclaimed_bytes(),
                reclaimed_debt_bytes: debt_reclaim.owned_bytes,
                cause,
            })
        }
    }
}

/// Conservative maximum additional physical bytes that an admission must
/// reserve.  It includes the durable pending journal, complete new shard, and
/// new manifest simultaneously visible during the crash window.
#[must_use]
pub(crate) const fn bounded_physical_bytes() -> u64 {
    MAX_TRANSACTION_BYTES
}

/// Test-only read path used by writer integration tests.  It authenticates the
/// stable key, manifest chain, and selected fixed shard without enumerating
/// the primary WAL or changing any ledger object.
#[cfg(test)]
pub(crate) fn contains_for_test(
    home: &Path,
    handle: &[u8; 32],
    expected: &ContextEvidenceReceipt,
) -> Result<bool> {
    let mut budget = IoBudget::default();
    let ledger = open_ledger_directory(home)?;
    let stages = list_entries(&ledger.dir, &ledger.display_path, &mut budget)?;
    recover_windows_empty_stages(&ledger, &stages, &mut budget)?;
    let names = list_entries(&ledger.dir, &ledger.display_path, &mut budget)?;
    validate_names(&names)?;
    anyhow::ensure!(
        names.iter().any(|name| name == LEDGER_KEY),
        "receipt ledger key is missing"
    );
    anyhow::ensure!(
        !names.iter().any(|name| name == PENDING),
        "receipt ledger has unresolved pending evidence"
    );
    let key_display = ledger.display_path.join(LEDGER_KEY);
    let key_body = read_child(
        &ledger.dir,
        LEDGER_KEY,
        &key_display,
        MAX_LEDGER_KEY_FILE_BYTES,
        &mut budget,
    )?;
    let key: [u8; 32] = crate::wal::compaction::maybe_unwrap_dpapi(&key_body, &key_display)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("receipt ledger key has invalid length"))?;
    let mut read_accounting = MutationAccounting::default();
    let mut manifests = read_manifests(
        &ledger,
        &key,
        &names,
        None,
        &mut budget,
        &mut read_accounting,
    )?;
    anyhow::ensure!(
        read_accounting.retained_bytes()? == 0 && read_accounting.reclaimed_bytes() == 0,
        "test-only receipt lookup attempted a ledger mutation"
    );
    let Some(active) = choose_active_manifest(&mut manifests)? else {
        return Ok(false);
    };
    require_anchor(&ledger, &key, &active, &mut budget)?;
    let shard_index = shard_for_handle(&key, handle) as usize;
    let entry = active.entries[shard_index];
    if !entry.present {
        return Ok(false);
    }
    let shard = read_shard_for_entry(&ledger, shard_index as u8, entry, &key, &mut budget)?;
    match shard.handles.binary_search(handle) {
        Ok(position) => {
            anyhow::ensure!(
                receipt_at(&shard, position)? == *expected,
                "receipt ledger handle payload collision"
            );
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Authenticated, bounded operator view of the current receipt-ledger head.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ReceiptLedgerHead {
    pub(crate) schema_version: u16,
    pub(crate) generation: u64,
    pub(crate) total_records: u32,
    pub(crate) manifest_sha256: String,
    pub(crate) manifest_hmac_sha256: String,
    pub(crate) anchor_hmac_sha256: String,
    pub(crate) ledger_v1_first_emission: bool,
}

/// Exact closed receipt frame selected by one opaque handle.  No path, source,
/// account, or imported content is introduced by this forensic projection.
#[derive(Debug, serde::Serialize)]
pub(crate) struct AuthenticatedReceiptRecord {
    pub(crate) receipt: ContextEvidenceReceipt,
    pub(crate) exact_frame_sha256: String,
    pub(crate) exact_frame_hex: String,
}

/// Read-only query result. A present head with `receipt: None` is authenticated
/// absence for the requested handle, not an absent or uninitialized ledger.
#[derive(Debug, serde::Serialize)]
pub(crate) struct AuthenticatedReceiptLedgerView {
    pub(crate) head: ReceiptLedgerHead,
    pub(crate) receipt: Option<AuthenticatedReceiptRecord>,
}

/// Authenticate the current ledger head and, optionally, one exact receipt.
///
/// The query enumerates only the closed ledger/anchor namespaces, reads one
/// fixed manifest, one fixed anchor, and at most one fixed shard. It never
/// scans primary WAL history and never repairs or mutates an in-flight state;
/// pending/staged/two-head state is refused so an operator cannot mistake an
/// unstable snapshot for forensic evidence.
pub(crate) fn read_authenticated_ledger(
    home: &Path,
    handle: Option<&[u8; 32]>,
) -> Result<Option<AuthenticatedReceiptLedgerView>> {
    let Some(ledger) = open_ledger_directory_existing(home)? else {
        return Ok(None);
    };
    let mut budget = IoBudget::default();
    let names = list_entries(&ledger.dir, &ledger.display_path, &mut budget)?;
    validate_names(&names)?;
    anyhow::ensure!(
        names.iter().any(|name| name == LEDGER_KEY),
        "receipt ledger key is missing"
    );
    anyhow::ensure!(
        !names.iter().any(|name| name == PENDING),
        "receipt ledger has unresolved pending evidence"
    );
    let key_display = ledger.display_path.join(LEDGER_KEY);
    let key_body = read_child(
        &ledger.dir,
        LEDGER_KEY,
        &key_display,
        MAX_LEDGER_KEY_FILE_BYTES,
        &mut budget,
    )?;
    let key: [u8; 32] = crate::wal::compaction::maybe_unwrap_dpapi(&key_body, &key_display)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("receipt ledger key has invalid length"))?;
    let mut read_accounting = MutationAccounting::default();
    let mut manifests = read_manifests(
        &ledger,
        &key,
        &names,
        None,
        &mut budget,
        &mut read_accounting,
    )?;
    anyhow::ensure!(
        read_accounting.retained_bytes()? == 0
            && read_accounting.reclaimed_bytes() == 0
            && read_accounting.removed_preexisting.is_empty(),
        "read-only receipt query attempted a ledger mutation"
    );
    anyhow::ensure!(
        manifests.len() <= 1,
        "receipt ledger read refused an unstable two-manifest state"
    );
    let Some(active) = manifests.pop() else {
        anyhow::bail!("receipt ledger key exists without an authenticated manifest");
    };
    let anchor = read_required_anchor(&ledger, &key, &active, &mut budget)?;
    let record = match handle {
        None => None,
        Some(handle) => {
            let shard_index = shard_for_handle(&key, handle) as usize;
            let entry = active.entries[shard_index];
            if !entry.present {
                None
            } else {
                let shard =
                    read_shard_for_entry(&ledger, shard_index as u8, entry, &key, &mut budget)?;
                match shard.handles.binary_search(handle) {
                    Err(_) => None,
                    Ok(position) => {
                        let raw_record = record_at(&shard.bytes, position)?;
                        let frame_len =
                            usize::from(u16::from_le_bytes(raw_record[..2].try_into().unwrap()));
                        anyhow::ensure!(
                            frame_len <= FRAME_MAX_BYTES,
                            "receipt ledger frame length exceeds its fixed record"
                        );
                        let exact_frame = &raw_record[8..8 + frame_len];
                        let (stored_handle, receipt) = decode_record(raw_record)?;
                        anyhow::ensure!(
                            stored_handle == *handle,
                            "receipt ledger selected record handle mismatch"
                        );
                        Some(AuthenticatedReceiptRecord {
                            receipt,
                            exact_frame_sha256: hex::encode(sha256(exact_frame)),
                            exact_frame_hex: hex::encode(exact_frame),
                        })
                    }
                }
            }
        }
    };
    Ok(Some(AuthenticatedReceiptLedgerView {
        head: ReceiptLedgerHead {
            schema_version: FORMAT_VERSION,
            generation: active.generation,
            total_records: active.total_records,
            manifest_sha256: hex::encode(sha256(&active.bytes)),
            manifest_hmac_sha256: hex::encode(&active.bytes[MANIFEST_BYTES - TAG_BYTES..]),
            anchor_hmac_sha256: hex::encode(&anchor[ANCHOR_BYTES - TAG_BYTES..]),
            ledger_v1_first_emission: LEDGER_V1_IS_FIRST_CONTEXT_EVIDENCE_RECEIPT_PRODUCER,
        },
        receipt: record,
    }))
}

fn open_ledger_directory_existing(home: &Path) -> Result<Option<store::BoundDirectory>> {
    let ledger = home.join("wal").join(LEDGER_DIR);
    let anchor = home.parent().unwrap_or(home);
    store::open_bound_directory_from_trusted_anchor(
        anchor,
        &ledger,
        false,
        "Context Evidence receipt ledger",
    )
}

fn read_required_anchor(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    manifest: &Manifest,
    budget: &mut IoBudget,
) -> Result<Vec<u8>> {
    let wal = open_anchor_directory_for_ledger(ledger, false)?;
    let names = list_entries(&wal.dir, &wal.display_path, budget)?;
    anyhow::ensure!(
        names.len() <= 2,
        "receipt ledger read anchor namespace is oversized"
    );
    let expected = anchor_file_name(manifest.generation);
    let predecessor =
        (manifest.previous_generation != 0).then(|| anchor_file_name(manifest.previous_generation));
    anyhow::ensure!(
        names.iter().all(|name| {
            name == &expected || predecessor.as_ref().is_some_and(|prior| name == prior)
        }),
        "receipt ledger read anchor namespace has rollback/replay evidence"
    );
    let display = wal.display_path.join(&expected);
    let bytes = read_child(&wal.dir, &expected, &display, ANCHOR_BYTES, budget)?;
    validate_anchor(&bytes, key, manifest)?;
    Ok(bytes)
}

fn open_ledger_directory(home: &Path) -> Result<store::BoundDirectory> {
    let wal = home.join("wal");
    let ledger = wal.join(LEDGER_DIR);
    let anchor = home.parent().unwrap_or(home);
    store::open_bound_directory_from_trusted_anchor(
        anchor,
        &ledger,
        true,
        "Context Evidence receipt ledger",
    )?
    .context("Context Evidence receipt ledger directory is unavailable")
}

fn open_anchor_directory_for_ledger(
    ledger: &store::BoundDirectory,
    create: bool,
) -> Result<store::BoundDirectory> {
    let wal = ledger
        .display_path
        .parent()
        .context("receipt ledger has no WAL parent")?;
    let home = wal.parent().context("receipt WAL has no home parent")?;
    let anchor = wal.join(ANCHOR_DIR);
    store::open_bound_directory_from_trusted_anchor(
        home,
        &anchor,
        create,
        "Context Evidence receipt external anchor",
    )?
    .context("Context Evidence receipt external anchor directory is unavailable")
}

fn anchor_file_name(generation: u64) -> String {
    format!("{ANCHOR_PREFIX}{generation:016x}.v1")
}

fn parse_anchor_name(name: &str) -> Option<u64> {
    let inner = name.strip_prefix(ANCHOR_PREFIX)?.strip_suffix(".v1")?;
    (inner.len() == 16 && inner.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(inner, 16).ok())
        .flatten()
}

fn anchor_bytes(key: &[u8; 32], manifest: &Manifest) -> Vec<u8> {
    let mut bytes = vec![0; ANCHOR_BYTES];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[12..20].copy_from_slice(&manifest.generation.to_le_bytes());
    bytes[20..52].copy_from_slice(&sha256(key));
    bytes[52..84].copy_from_slice(&sha256(&manifest.bytes));
    let tag = tag(key, DOMAIN_ANCHOR, &bytes[..ANCHOR_BYTES - TAG_BYTES]);
    bytes[ANCHOR_BYTES - TAG_BYTES..].copy_from_slice(&tag);
    bytes
}

fn validate_anchor(bytes: &[u8], key: &[u8; 32], manifest: &Manifest) -> Result<()> {
    anyhow::ensure!(
        bytes.len() == ANCHOR_BYTES,
        "receipt ledger anchor has non-fixed size"
    );
    verify_tag(key, DOMAIN_ANCHOR, bytes)?;
    anyhow::ensure!(
        &bytes[..8] == ANCHOR_MAGIC
            && u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == FORMAT_VERSION
            && bytes[10..12].iter().all(|byte| *byte == 0),
        "receipt ledger anchor header is invalid"
    );
    anyhow::ensure!(
        u64::from_le_bytes(bytes[12..20].try_into().unwrap()) == manifest.generation,
        "receipt ledger anchor generation mismatch"
    );
    anyhow::ensure!(
        bytes[20..52] == sha256(key),
        "receipt ledger anchor key fingerprint mismatch"
    );
    anyhow::ensure!(
        bytes[52..84] == sha256(&manifest.bytes),
        "receipt ledger anchor manifest fingerprint mismatch"
    );
    Ok(())
}

fn publish_anchor(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    manifest: &Manifest,
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let wal = open_anchor_directory_for_ledger(ledger, true)?;
    let stages = list_entries(&wal.dir, &wal.display_path, budget)?;
    recover_windows_empty_stages(&wal, &stages, budget)?;
    let names = list_entries(&wal.dir, &wal.display_path, budget)?;
    anyhow::ensure!(
        names.len() <= 2,
        "receipt ledger anchor publication namespace is oversized"
    );
    anyhow::ensure!(
        names.iter().all(
            |candidate| parse_anchor_name(candidate).is_some_and(|generation| {
                generation == manifest.generation || generation == manifest.previous_generation
            })
        ),
        "receipt ledger anchor publication namespace is not the authenticated adjacent transition"
    );
    let name = anchor_file_name(manifest.generation);
    let display = wal.display_path.join(&name);
    match wal.dir.symlink_metadata(OsStr::new(&name)) {
        Ok(_) => {
            let bytes = read_child(&wal.dir, &name, &display, ANCHOR_BYTES, budget)?;
            validate_anchor(&bytes, key, manifest)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let bytes = anchor_bytes(key, manifest);
            write_new_child_accounted(
                &wal,
                ObjectNamespace::Anchor,
                &name,
                &bytes,
                ANCHOR_BYTES as u64,
                accounting,
            )?;
            #[cfg(test)]
            inject_transaction_failure(ledger, TestTransactionFailure::AfterAnchor)?;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| "inspect receipt ledger external anchor"),
    }
}

fn require_anchor(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    manifest: &Manifest,
    budget: &mut IoBudget,
) -> Result<()> {
    let wal = open_anchor_directory_for_ledger(ledger, false)?;
    let stages = list_entries(&wal.dir, &wal.display_path, budget)?;
    recover_windows_empty_stages(&wal, &stages, budget)?;
    let names = list_entries(&wal.dir, &wal.display_path, budget)?;
    anyhow::ensure!(
        names.len() <= 4,
        "receipt ledger anchor directory entry cap exceeded"
    );
    let expected = anchor_file_name(manifest.generation);
    let predecessor =
        (manifest.previous_generation != 0).then(|| anchor_file_name(manifest.previous_generation));
    anyhow::ensure!(
        names.iter().all(
            |name| name == &expected || predecessor.as_ref().is_some_and(|prior| name == prior)
        ),
        "receipt ledger anchor namespace has rollback/replay evidence"
    );
    let display = wal.display_path.join(&expected);
    let bytes = read_child(&wal.dir, &expected, &display, ANCHOR_BYTES, budget)?;
    validate_anchor(&bytes, key, manifest)
}

fn remove_anchor(
    ledger: &store::BoundDirectory,
    generation: u64,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let wal = open_anchor_directory_for_ledger(ledger, false)?;
    let name = anchor_file_name(generation);
    let display = wal.display_path.join(&name);
    match wal.dir.symlink_metadata(OsStr::new(&name)) {
        Ok(_) => remove_exact_accounted(&wal, ObjectNamespace::Anchor, &name, accounting),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect old receipt ledger anchor {}", display.display())),
    }
}

fn list_entries(dir: &Dir, display: &Path, budget: &mut IoBudget) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in dir
        .entries()
        .with_context(|| format!("enumerate receipt ledger {}", display.display()))?
    {
        let entry = entry
            .with_context(|| format!("read receipt ledger entry under {}", display.display()))?;
        budget.entry()?;
        anyhow::ensure!(
            names.len() < MAX_DIRECTORY_ENTRIES,
            "receipt ledger directory entry cap exceeded"
        );
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("receipt ledger entry name is not UTF-8")?;
        names.push(name.to_owned());
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(windows)]
fn recover_windows_empty_stages(
    directory: &store::BoundDirectory,
    names: &[String],
    _budget: &mut IoBudget,
) -> Result<()> {
    for name in names {
        let Some(uuid) = name.strip_prefix(".neoth-private-empty-") else {
            continue;
        };
        anyhow::ensure!(
            uuid::Uuid::parse_str(uuid).is_ok(),
            "unexpected receipt ledger Windows stage name"
        );
        let display = directory.display_path.join(name);
        let (file, binding) =
            store::open_bound_regular_file(&directory.dir, OsStr::new(name), &display)?;
        let metadata = file
            .metadata()
            .context("inspect receipt ledger Windows stage")?;
        anyhow::ensure!(
            metadata.len() == 0,
            "non-empty receipt ledger Windows stage is ambiguous"
        );
        crate::wal::win_native::verify_private_dacl(&display)
            .context("receipt ledger Windows stage private DACL verification failed")?;
        drop(file);
        binding.remove_bound_file(&directory.dir, OsStr::new(name), &display)?;
        store::sync_parent_directory(&directory.dir, &directory.display_path)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn recover_windows_empty_stages(
    _directory: &store::BoundDirectory,
    _names: &[String],
    _budget: &mut IoBudget,
) -> Result<()> {
    Ok(())
}

fn validate_names(names: &[String]) -> Result<()> {
    for name in names {
        anyhow::ensure!(
            name == LEDGER_KEY
                || name == PENDING
                || parse_manifest_name(name).is_some()
                || parse_shard_name(name).is_some(),
            "unexpected receipt ledger namespace entry"
        );
    }
    Ok(())
}

fn load_or_initialize_key(
    ledger: &store::BoundDirectory,
    names: &[String],
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<[u8; 32]> {
    let key_display = ledger.display_path.join(LEDGER_KEY);
    if names.iter().any(|name| name == LEDGER_KEY) {
        let body = read_child(
            &ledger.dir,
            LEDGER_KEY,
            &key_display,
            MAX_LEDGER_KEY_FILE_BYTES,
            budget,
        )?;
        let raw = crate::wal::compaction::maybe_unwrap_dpapi(&body, &key_display)
            .context("decode stable Context Evidence receipt ledger key")?;
        return raw.try_into().map_err(|_| {
            anyhow::anyhow!("Context Evidence receipt ledger key has invalid length")
        });
    }
    anyhow::ensure!(
        names.is_empty(),
        "Context Evidence receipt ledger key is missing beside durable evidence"
    );
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).context("OS RNG unavailable for receipt ledger key")?;
    let encoded = crate::wal::compaction::encode_key_for_storage(&key_display, &raw)
        .context("encode stable Context Evidence receipt ledger key")?;
    write_new_child_accounted(
        ledger,
        ObjectNamespace::Ledger,
        LEDGER_KEY,
        &encoded,
        MAX_LEDGER_KEY_FILE_BYTES as u64,
        accounting,
    )?;
    #[cfg(test)]
    inject_transaction_failure(ledger, TestTransactionFailure::AfterKey)?;
    Ok(raw)
}

fn recover_state(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<Option<Manifest>> {
    let stages = list_entries(&ledger.dir, &ledger.display_path, budget)?;
    recover_windows_empty_stages(ledger, &stages, budget)?;
    let names = list_entries(&ledger.dir, &ledger.display_path, budget)?;
    validate_names(&names)?;
    let pending_name = names.iter().any(|name| name == PENDING);
    let pending = if pending_name {
        let pending_display = ledger.display_path.join(PENDING);
        let bytes = read_child(
            &ledger.dir,
            PENDING,
            &pending_display,
            PENDING_BYTES,
            budget,
        )?;
        match parse_pending(&bytes, key) {
            Ok(pending) => Some(pending),
            Err(_) => {
                recover_torn_pending(ledger, key, &names, budget, accounting)?;
                None
            }
        }
    } else {
        None
    };
    let mut manifests = read_manifests(ledger, key, &names, pending.as_ref(), budget, accounting)?;
    if let Some(pending) = pending {
        recover_pending(ledger, key, &mut manifests, pending, budget, accounting)?;
        manifests = read_manifests(
            ledger,
            key,
            &list_entries(&ledger.dir, &ledger.display_path, budget)?,
            None,
            budget,
            accounting,
        )?;
    }
    let active = choose_active_manifest(&mut manifests)?;
    if let Some(ref manifest) = active {
        require_anchor(ledger, key, manifest, budget)?;
        cleanup_after_commit(ledger, key, manifest, budget, accounting)?;
        if manifest.previous_generation != 0 {
            remove_anchor(ledger, manifest.previous_generation, accounting)?;
        }
    } else {
        // An unattached shard is never a clean empty ledger.  Accepting it as
        // empty would let a torn/replayed transaction erase append-once
        // history; recovery is allowed to discard only a journal that proves
        // its successor shard never committed.
        let names = list_entries(&ledger.dir, &ledger.display_path, budget)?;
        anyhow::ensure!(
            names.iter().all(|name| name == LEDGER_KEY),
            "receipt ledger has evidence without an authenticated manifest"
        );
    }
    Ok(active)
}

fn read_manifests(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    names: &[String],
    pending: Option<&Pending>,
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<Vec<Manifest>> {
    let mut manifests = Vec::new();
    for name in names {
        if parse_manifest_name(name).is_some() {
            let display = ledger.display_path.join(name);
            let bytes = read_child(&ledger.dir, name, &display, MANIFEST_BYTES, budget)?;
            let manifest = match parse_manifest(&bytes, key) {
                Ok(manifest) => manifest,
                Err(_error)
                    if pending.is_some_and(|pending| {
                        parse_manifest_name(name) == Some(pending.new_generation)
                    }) =>
                {
                    // The pending journal fully authenticates the exact
                    // successor bytes. A direct canonical manifest that
                    // tore before its file sync is therefore safely
                    // removed and re-published from that journal.
                    remove_exact_accounted(ledger, ObjectNamespace::Ledger, name, accounting)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            anyhow::ensure!(
                parse_manifest_name(name) == Some(manifest.generation),
                "receipt ledger manifest filename/generation mismatch"
            );
            manifests.push(manifest);
        }
    }
    anyhow::ensure!(manifests.len() <= 2, "too many receipt ledger manifests");
    Ok(manifests)
}

fn recover_torn_pending(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    names: &[String],
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    // A partially written direct pending file is recoverable only before any
    // successor object exists.  Confirm the remaining namespace is exactly a
    // single authenticated baseline (or a fresh key), then remove that exact
    // pending object.  Any extra generation/shard is ambiguous and remains a
    // hard failure rather than being guessed away.
    let manifests = read_manifests(ledger, key, names, None, budget, accounting)?;
    let mut manifests = manifests;
    let active = choose_active_manifest(&mut manifests)?;
    for name in names {
        if let Some((shard, slot, generation)) = parse_shard_name(name) {
            let Some(active) = active.as_ref() else {
                anyhow::bail!("torn receipt ledger pending has successor shard evidence");
            };
            let entry = active.entries[shard as usize];
            anyhow::ensure!(
                entry.present && entry.slot == slot && entry.generation == generation,
                "torn receipt ledger pending has unbound shard evidence"
            );
        }
    }
    remove_pending_accounted(ledger, accounting)
}

fn recover_pending(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    manifests: &mut Vec<Manifest>,
    pending: Pending,
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    anyhow::ensure!(
        manifests.len() <= 2,
        "receipt ledger pending state has too many manifests"
    );
    let manifest_name = manifest_file_name(pending.new_generation);
    let shard_name = shard_file_name(pending.shard, pending.slot, pending.new_generation);
    let old_index = manifests
        .iter()
        .position(|manifest| sha256(&manifest.bytes) == pending.old_manifest_sha256);
    let new_index = manifests
        .iter()
        .position(|manifest| sha256(&manifest.bytes) == pending.new_manifest_sha256);

    let old_is_bound = match old_index {
        Some(index) => {
            let old = &manifests[index];
            old.generation == pending.manifest.previous_generation
                && pending.manifest.previous_sha256 == sha256(&old.bytes)
        }
        None => {
            pending.old_manifest_sha256 == ZERO_SHA
                && pending.manifest.previous_generation == 0
                && pending.manifest.previous_sha256 == ZERO_SHA
        }
    };
    anyhow::ensure!(
        old_is_bound,
        "receipt ledger pending state does not bind its old manifest"
    );

    if let Some(index) = new_index {
        let committed = &manifests[index];
        anyhow::ensure!(
            committed.generation == pending.new_generation
                && committed.previous_generation == pending.manifest.previous_generation
                && committed.previous_sha256 == pending.manifest.previous_sha256,
            "receipt ledger pending committed manifest chain mismatch"
        );
        anyhow::ensure!(
            manifests.len() == usize::from(old_index.is_some()) + 1,
            "receipt ledger pending has an unbound manifest"
        );
        validate_pending_shard(ledger, key, &pending, &shard_name, budget)?;
        publish_anchor(ledger, key, committed, budget, accounting)?;
        remove_pending_accounted(ledger, accounting)?;
        return Ok(());
    }
    anyhow::ensure!(
        manifests.len() <= 1 && old_index.is_some() == (pending.old_manifest_sha256 != ZERO_SHA),
        "receipt ledger pending has an unbound manifest"
    );
    let shard_display = ledger.display_path.join(&shard_name);
    match ledger.dir.symlink_metadata(OsStr::new(&shard_name)) {
        Ok(_) => {
            let _ = shard_display;
            if !pending_shard_is_valid(ledger, key, &pending, &shard_name, budget)? {
                // Only this pre-manifest phase is unambiguous: the target name
                // is generation-unique and the authenticated pending journal
                // proves no successor manifest exists.  A direct canonical
                // shard that tore before sync can therefore be removed with
                // its exact journal and retried from the old manifest.
                remove_exact_accounted(ledger, ObjectNamespace::Ledger, &shard_name, accounting)?;
                remove_pending_accounted(ledger, accounting)?;
                return Ok(());
            }
            write_new_child_accounted(
                ledger,
                ObjectNamespace::Ledger,
                &manifest_name,
                &pending.manifest.bytes,
                MANIFEST_BYTES as u64,
                accounting,
            )?;
            #[cfg(test)]
            inject_transaction_failure(ledger, TestTransactionFailure::AfterManifest)?;
            publish_anchor(ledger, key, &pending.manifest, budget, accounting)?;
            remove_pending_accounted(ledger, accounting)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The journal is durable but the new shard was never committed.
            // Removing only the exact authenticated journal rolls this attempt
            // back; the next append starts from the old authenticated state.
            remove_pending_accounted(ledger, accounting)?;
        }
        Err(error) => return Err(error).with_context(|| "inspect receipt ledger pending shard"),
    }
    Ok(())
}

fn validate_pending_shard(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    pending: &Pending,
    shard_name: &str,
    budget: &mut IoBudget,
) -> Result<()> {
    let display = ledger.display_path.join(shard_name);
    let bytes = read_child(&ledger.dir, shard_name, &display, SHARD_BYTES, budget)?;
    let entry = pending.manifest.entries[pending.shard as usize];
    let _ = parse_shard(&bytes, pending.shard, entry, key)?;
    anyhow::ensure!(
        sha256(&bytes) == pending.new_shard_sha256,
        "receipt ledger pending shard digest mismatch"
    );
    Ok(())
}

fn pending_shard_is_valid(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    pending: &Pending,
    shard_name: &str,
    budget: &mut IoBudget,
) -> Result<bool> {
    let display = ledger.display_path.join(shard_name);
    let bytes = read_child(&ledger.dir, shard_name, &display, SHARD_BYTES, budget)?;
    let entry = pending.manifest.entries[pending.shard as usize];
    Ok(parse_shard(&bytes, pending.shard, entry, key).is_ok()
        && sha256(&bytes) == pending.new_shard_sha256)
}

fn choose_active_manifest(manifests: &mut Vec<Manifest>) -> Result<Option<Manifest>> {
    match manifests.len() {
        0 => Ok(None),
        1 => Ok(manifests.pop()),
        2 => {
            manifests.sort_by_key(|manifest| manifest.generation);
            let older = &manifests[0];
            let newer = &manifests[1];
            anyhow::ensure!(
                newer.previous_generation == older.generation
                    && newer.previous_sha256 == sha256(&older.bytes),
                "receipt ledger manifests are not one authenticated generation chain"
            );
            Ok(manifests.pop())
        }
        _ => anyhow::bail!("too many receipt ledger manifests"),
    }
}

fn cleanup_after_commit(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    active: &Manifest,
    budget: &mut IoBudget,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let names = list_entries(&ledger.dir, &ledger.display_path, budget)?;
    validate_names(&names)?;
    let mut orphan_shards = Vec::new();
    for name in &names {
        if let Some(generation) = parse_manifest_name(name) {
            if generation != active.generation {
                anyhow::ensure!(
                    generation < active.generation,
                    "receipt ledger manifest replay/rollback evidence detected"
                );
                remove_exact_accounted(ledger, ObjectNamespace::Ledger, name, accounting)?;
            }
        }
        if let Some((shard, slot, generation)) = parse_shard_name(name) {
            let referenced = active.entries[shard as usize];
            if !(referenced.present
                && referenced.slot == slot
                && referenced.generation == generation)
            {
                anyhow::ensure!(
                    generation < active.generation,
                    "receipt ledger future shard evidence detected"
                );
                orphan_shards.push((name.clone(), shard, slot, generation));
            }
        }
    }
    anyhow::ensure!(
        orphan_shards.len() <= MAX_RECOVERY_ORPHANS,
        "receipt ledger orphan recovery bound exceeded"
    );
    for (name, shard, slot, generation) in orphan_shards {
        let display = ledger.display_path.join(&name);
        let bytes = read_child(&ledger.dir, &name, &display, SHARD_BYTES, budget)?;
        anyhow::ensure!(
            bytes.len() == SHARD_BYTES,
            "receipt ledger orphan shard has non-fixed size"
        );
        let count = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
        let entry = ManifestEntry {
            present: true,
            slot,
            count,
            generation,
            shard_sha256: sha256(&bytes),
        };
        // A valid but unreferenced old generation can only be discarded after
        // its full fixed object authenticates and validates its own binding.
        let _ = parse_shard(&bytes, shard, entry, key)?;
        remove_exact_accounted(ledger, ObjectNamespace::Ledger, &name, accounting)?;
    }
    Ok(())
}

fn read_shard_for_entry(
    ledger: &store::BoundDirectory,
    shard: u8,
    entry: ManifestEntry,
    key: &[u8; 32],
    budget: &mut IoBudget,
) -> Result<Shard> {
    let name = shard_file_name(shard, entry.slot, entry.generation);
    let display = ledger.display_path.join(&name);
    let bytes = read_child(&ledger.dir, &name, &display, SHARD_BYTES, budget)?;
    anyhow::ensure!(
        sha256(&bytes) == entry.shard_sha256,
        "receipt ledger shard digest mismatch"
    );
    parse_shard(&bytes, shard, entry, key)
}

fn empty_shard(shard: u8, generation: u64) -> Shard {
    Shard {
        shard,
        slot: 0,
        generation,
        count: 0,
        bytes: vec![0; SHARD_BYTES],
        handles: Vec::with_capacity(RECORDS_PER_SHARD),
    }
}

fn insert_record(
    shard: &mut Shard,
    position: usize,
    handle: &[u8; 32],
    frame: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        shard.count < RECORDS_PER_SHARD,
        "receipt ledger shard capacity exhausted"
    );
    anyhow::ensure!(
        frame.len() <= FRAME_MAX_BYTES,
        "receipt ledger frame exceeds fixed record capacity"
    );
    let records = shard_records_mut(&mut shard.bytes);
    let from = position
        .checked_mul(RECORD_BYTES)
        .context("receipt ledger record offset overflow")?;
    let end = shard
        .count
        .checked_mul(RECORD_BYTES)
        .context("receipt ledger record end overflow")?;
    records.copy_within(from..end, from + RECORD_BYTES);
    let record = &mut records[from..from + RECORD_BYTES];
    record.fill(0);
    record[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    record[8..8 + frame.len()].copy_from_slice(frame);
    shard.handles.insert(position, *handle);
    shard.count += 1;
    Ok(())
}

fn ensure_insert_capacity(total_records: u32, shard_records: usize) -> Result<()> {
    anyhow::ensure!(
        usize::try_from(total_records)
            .ok()
            .is_some_and(|total| total < LIFETIME_CAPACITY),
        "receipt ledger lifetime capacity exhausted"
    );
    anyhow::ensure!(
        shard_records < RECORDS_PER_SHARD,
        "receipt ledger shard capacity exhausted"
    );
    Ok(())
}

fn receipt_at(shard: &Shard, position: usize) -> Result<ContextEvidenceReceipt> {
    let record = record_at(&shard.bytes, position)?;
    decode_record(record).map(|(_, receipt)| receipt)
}

fn next_manifest(
    prior: Option<&Manifest>,
    generation: u64,
    shard: usize,
    slot: u8,
    count: usize,
    shard_sha256: [u8; SHA_BYTES],
) -> Result<Manifest> {
    let (previous_generation, previous_sha256, mut entries, old_total) = match prior {
        Some(manifest) => (
            manifest.generation,
            sha256(&manifest.bytes),
            manifest.entries,
            manifest.total_records,
        ),
        None => (0, ZERO_SHA, [ManifestEntry::EMPTY; SHARD_COUNT], 0),
    };
    anyhow::ensure!(
        generation > previous_generation,
        "receipt ledger generation is not monotonic"
    );
    anyhow::ensure!(
        count <= RECORDS_PER_SHARD,
        "receipt ledger shard count overflow"
    );
    let old_count = u32::from(entries[shard].count);
    let new_count = u32::try_from(count).context("receipt ledger shard count conversion")?;
    let total_records = old_total
        .checked_sub(old_count)
        .context("receipt ledger manifest total underflow")?
        .checked_add(new_count)
        .context("receipt ledger manifest total overflow")?;
    anyhow::ensure!(
        usize::try_from(total_records)
            .ok()
            .is_some_and(|total| total <= LIFETIME_CAPACITY),
        "receipt ledger lifetime capacity exhausted"
    );
    entries[shard] = ManifestEntry {
        present: true,
        slot,
        count: u16::try_from(count).context("receipt ledger shard count does not fit u16")?,
        generation,
        shard_sha256,
    };
    Ok(Manifest {
        generation,
        previous_generation,
        previous_sha256,
        total_records,
        entries,
        bytes: vec![0; MANIFEST_BYTES],
    })
}

fn write_transaction(
    ledger: &store::BoundDirectory,
    key: &[u8; 32],
    pending: &Pending,
    shard: &Shard,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let pending_bytes = serialize_pending(pending, key)?;
    write_new_child_accounted(
        ledger,
        ObjectNamespace::Ledger,
        PENDING,
        &pending_bytes,
        PENDING_BYTES as u64,
        accounting,
    )?;
    #[cfg(test)]
    inject_transaction_failure(ledger, TestTransactionFailure::AfterPending)?;
    let shard_name = shard_file_name(pending.shard, pending.slot, pending.new_generation);
    write_new_child_accounted(
        ledger,
        ObjectNamespace::Ledger,
        &shard_name,
        &shard.bytes,
        SHARD_BYTES as u64,
        accounting,
    )?;
    #[cfg(test)]
    inject_transaction_failure(ledger, TestTransactionFailure::AfterShard)?;
    let manifest_name = manifest_file_name(pending.new_generation);
    write_new_child_accounted(
        ledger,
        ObjectNamespace::Ledger,
        &manifest_name,
        &pending.manifest.bytes,
        MANIFEST_BYTES as u64,
        accounting,
    )?;
    #[cfg(test)]
    inject_transaction_failure(ledger, TestTransactionFailure::AfterManifest)?;
    Ok(())
}

enum CanonicalWrite {
    Published { bytes: u64 },
    RolledBackDurably { cause: anyhow::Error },
    PossiblyRetained { bytes: u64, cause: anyhow::Error },
}

fn write_new_child_accounted(
    directory: &store::BoundDirectory,
    namespace: ObjectNamespace,
    name: &str,
    bytes: &[u8],
    maximum_bytes: u64,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let actual_bytes =
        u64::try_from(bytes.len()).context("receipt ledger object length does not fit u64")?;
    anyhow::ensure!(
        actual_bytes <= maximum_bytes,
        "receipt ledger object exceeds its precharged maximum"
    );
    // This charge deliberately precedes the direct create call.  The store
    // primitive can have crossed its platform-specific canonical-name commit
    // before a later binding/metadata check reports an error.
    let token = accounting.precharge(namespace, name, maximum_bytes)?;
    match write_new_child(directory, namespace, name, bytes, maximum_bytes) {
        CanonicalWrite::Published { bytes } => accounting.publication_length(token, bytes),
        CanonicalWrite::RolledBackDurably { cause } => {
            accounting.rolled_back_durably(token)?;
            Err(cause)
        }
        CanonicalWrite::PossiblyRetained { bytes, cause } => {
            accounting.publication_length(token, bytes)?;
            Err(cause)
        }
    }
}

fn write_new_child(
    directory: &store::BoundDirectory,
    namespace: ObjectNamespace,
    name: &str,
    bytes: &[u8],
    retained_bound: u64,
) -> CanonicalWrite {
    let _ = namespace;
    let display = directory.display_path.join(name);
    let created = store::create_private_regular_file_child_create_new(
        &directory.dir,
        OsStr::new(name),
        &display,
    )
    .with_context(|| "create canonical receipt ledger object");
    let (mut file, binding) = match created {
        Ok(created) => created,
        Err(cause) => {
            // The platform helper may have committed the canonical name before
            // a later metadata/binding check failed.  Without the retained
            // binding there is no safe rollback proof, so keep the complete
            // precharge even when the visible file later appears empty.
            return CanonicalWrite::PossiblyRetained {
                bytes: retained_bound,
                cause,
            };
        }
    };
    #[cfg(test)]
    let test_object = canonical_object_for_test(namespace, name);
    let published = (|| -> Result<()> {
        #[cfg(test)]
        inject_canonical_write_failure(
            &directory.display_path,
            test_object,
            TestCanonicalWriteFailure::AfterCreate,
        )?;
        file.write_all(bytes)
            .with_context(|| "write canonical receipt ledger object")?;
        #[cfg(test)]
        inject_canonical_write_failure(
            &directory.display_path,
            test_object,
            TestCanonicalWriteFailure::AfterWrite,
        )?;
        file.sync_all()
            .with_context(|| "sync canonical receipt ledger object")?;
        #[cfg(test)]
        inject_canonical_write_failure(
            &directory.display_path,
            test_object,
            TestCanonicalWriteFailure::AfterFileSync,
        )?;
        anyhow::ensure!(
            binding.matches_regular_file_child_readonly(
                &directory.dir,
                OsStr::new(name),
                &display
            )?,
            "canonical receipt ledger object changed before publication"
        );
        store::sync_parent_directory(&directory.dir, &directory.display_path)
            .context("sync canonical receipt ledger object parent")?;
        #[cfg(test)]
        inject_canonical_write_failure(
            &directory.display_path,
            test_object,
            TestCanonicalWriteFailure::AfterParentSync,
        )?;
        Ok(())
    })();
    if let Err(cause) = published {
        drop(file);
        #[cfg(test)]
        if let Err(cleanup_error) = inject_canonical_write_failure(
            &directory.display_path,
            test_object,
            TestCanonicalWriteFailure::RollbackRemove,
        ) {
            return CanonicalWrite::PossiblyRetained {
                bytes: retained_bound,
                cause: cause.context(format!(
                    "canonical receipt ledger rollback failed: {cleanup_error:#}"
                )),
            };
        }
        let cleanup = binding.remove_bound_file(&directory.dir, OsStr::new(name), &display);
        return match cleanup {
            Ok(()) => {
                #[cfg(test)]
                let rollback_sync = inject_canonical_write_failure(
                    &directory.display_path,
                    test_object,
                    TestCanonicalWriteFailure::RollbackParentSync,
                )
                .and_then(|()| {
                    store::sync_parent_directory(&directory.dir, &directory.display_path)
                });
                #[cfg(not(test))]
                let rollback_sync =
                    store::sync_parent_directory(&directory.dir, &directory.display_path);
                match rollback_sync.context("sync canonical receipt ledger rollback") {
                    Ok(()) => CanonicalWrite::RolledBackDurably { cause },
                    Err(cleanup_error) => CanonicalWrite::PossiblyRetained {
                        bytes: retained_bound,
                        cause: cause.context(format!(
                            "canonical receipt ledger rollback durability failed: {cleanup_error:#}"
                        )),
                    },
                }
            }
            Err(cleanup_error) => CanonicalWrite::PossiblyRetained {
                bytes: retained_bound,
                cause: cause.context(format!(
                    "canonical receipt ledger rollback failed: {cleanup_error:#}"
                )),
            },
        };
    }
    CanonicalWrite::Published {
        bytes: u64::try_from(bytes.len()).unwrap_or(retained_bound),
    }
}

fn remove_exact_accounted(
    directory: &store::BoundDirectory,
    namespace: ObjectNamespace,
    name: &str,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    let removed_bytes = remove_exact_from(directory, name)?;
    accounting.removed_durably(namespace, name, removed_bytes)
}

fn remove_pending_accounted(
    ledger: &store::BoundDirectory,
    accounting: &mut MutationAccounting,
) -> Result<()> {
    remove_exact_accounted(ledger, ObjectNamespace::Ledger, PENDING, accounting)?;
    #[cfg(test)]
    inject_transaction_failure(ledger, TestTransactionFailure::AfterPendingRemoval)?;
    Ok(())
}

fn remove_exact_from(directory: &store::BoundDirectory, name: &str) -> Result<u64> {
    let display = directory.display_path.join(name);
    let (file, read_binding) =
        store::open_bound_regular_file(&directory.dir, OsStr::new(name), &display)?;
    let removed_bytes = file
        .metadata()
        .with_context(|| "inspect exact receipt ledger removal length")?
        .len();
    let removal = store::bind_regular_file_for_removal(
        &directory.dir,
        OsStr::new(name),
        &display,
        &read_binding,
    )?;
    drop(file);
    removal.remove_bound_file(&directory.dir, OsStr::new(name), &display)?;
    store::sync_parent_directory(&directory.dir, &directory.display_path)?;
    Ok(removed_bytes)
}

fn read_child(
    dir: &Dir,
    name: &str,
    display: &Path,
    ceiling: usize,
    budget: &mut IoBudget,
) -> Result<Vec<u8>> {
    let mut observed = 0u64;
    let result = store::read_regular_file_bounded_observed(
        dir,
        OsStr::new(name),
        display,
        ceiling,
        |read| {
            observed = read;
            Ok(())
        },
    );
    budget
        .read(usize::try_from(observed).context("receipt ledger read count does not fit usize")?)?;
    result
}

fn validate_exact_frame(
    handle: &[u8; 32],
    expected: &ContextEvidenceReceipt,
    frame: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        frame.len() <= FRAME_MAX_BYTES,
        "receipt ledger exact frame is oversized"
    );
    let decoded = crate::wal::frame::decode_frame(frame)
        .context("receipt ledger exact frame does not decode")?;
    anyhow::ensure!(
        decoded.header.total_len as usize == frame.len(),
        "receipt ledger exact frame has trailing bytes"
    );
    anyhow::ensure!(
        decoded.header.event_type == EVENT_TYPE_EXTENDED,
        "receipt ledger frame is not extended"
    );
    anyhow::ensure!(
        decoded.header.event_subtype == ExtendedSubtype::ContextEvidenceReceipt as u8,
        "receipt ledger frame is not ContextEvidenceReceipt"
    );
    let receipt = ContextEvidenceReceipt::decode(decoded.payload)
        .context("receipt ledger receipt payload is not closed")?;
    anyhow::ensure!(
        receipt == *expected && receipt.matches_opaque_handle(handle),
        "receipt ledger frame does not bind expected opaque receipt"
    );
    Ok(())
}

fn finalize_shard(shard: &mut Shard, key: &[u8; 32]) -> Result<()> {
    anyhow::ensure!(
        shard.count == shard.handles.len(),
        "receipt ledger shard handle index mismatch"
    );
    anyhow::ensure!(
        shard.count <= RECORDS_PER_SHARD,
        "receipt ledger shard count overflow"
    );
    let bytes = &mut shard.bytes;
    anyhow::ensure!(
        bytes.len() == SHARD_BYTES,
        "receipt ledger shard size mismatch"
    );
    bytes[..SHARD_HEADER_BYTES].fill(0);
    bytes[..8].copy_from_slice(SHARD_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10] = shard.shard;
    bytes[11] = shard.slot;
    bytes[12..14].copy_from_slice(&(shard.count as u16).to_le_bytes());
    bytes[16..24].copy_from_slice(&shard.generation.to_le_bytes());
    let records_sha = sha256(shard_records(bytes));
    bytes[24..56].copy_from_slice(&records_sha);
    let tag = tag(key, DOMAIN_SHARD, &bytes[..SHARD_BYTES - TAG_BYTES]);
    bytes[SHARD_BYTES - TAG_BYTES..].copy_from_slice(&tag);
    Ok(())
}

fn parse_shard(
    bytes: &[u8],
    expected_shard: u8,
    entry: ManifestEntry,
    key: &[u8; 32],
) -> Result<Shard> {
    anyhow::ensure!(
        bytes.len() == SHARD_BYTES,
        "receipt ledger shard has non-fixed size"
    );
    verify_tag(key, DOMAIN_SHARD, bytes)?;
    anyhow::ensure!(
        &bytes[..8] == SHARD_MAGIC,
        "receipt ledger shard magic mismatch"
    );
    anyhow::ensure!(
        u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == FORMAT_VERSION,
        "receipt ledger shard version mismatch"
    );
    anyhow::ensure!(
        bytes[10] == expected_shard && bytes[11] == entry.slot,
        "receipt ledger shard placement mismatch"
    );
    let count = usize::from(u16::from_le_bytes(bytes[12..14].try_into().unwrap()));
    anyhow::ensure!(
        count <= RECORDS_PER_SHARD && bytes[14..16].iter().all(|byte| *byte == 0),
        "receipt ledger shard count/reserved mismatch"
    );
    anyhow::ensure!(
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == entry.generation,
        "receipt ledger shard generation mismatch"
    );
    anyhow::ensure!(
        bytes[24..56] == sha256(shard_records(bytes)),
        "receipt ledger shard records digest mismatch"
    );
    anyhow::ensure!(
        entry.count as usize == count,
        "receipt ledger manifest/shard count mismatch"
    );
    let mut handles = Vec::with_capacity(count);
    let mut previous = None;
    for index in 0..RECORDS_PER_SHARD {
        let record = record_at(bytes, index)?;
        if index < count {
            let (handle, _) = decode_record(record)?;
            anyhow::ensure!(
                shard_for_handle(key, &handle) == expected_shard,
                "receipt ledger record has wrong keyed shard"
            );
            if let Some(prior) = previous {
                anyhow::ensure!(
                    prior < handle,
                    "receipt ledger records are not strictly sorted"
                );
            }
            previous = Some(handle);
            handles.push(handle);
        } else {
            anyhow::ensure!(
                record.iter().all(|byte| *byte == 0),
                "receipt ledger unused record is non-zero"
            );
        }
    }
    Ok(Shard {
        shard: expected_shard,
        slot: entry.slot,
        generation: entry.generation,
        count,
        bytes: bytes.to_vec(),
        handles,
    })
}

fn decode_record(record: &[u8]) -> Result<([u8; 32], ContextEvidenceReceipt)> {
    anyhow::ensure!(
        record.len() == RECORD_BYTES,
        "receipt ledger record size mismatch"
    );
    let frame_len = usize::from(u16::from_le_bytes(record[..2].try_into().unwrap()));
    anyhow::ensure!(
        (104..=FRAME_MAX_BYTES).contains(&frame_len),
        "receipt ledger record frame length invalid"
    );
    anyhow::ensure!(
        record[2..8].iter().all(|byte| *byte == 0),
        "receipt ledger record reserved bytes non-zero"
    );
    anyhow::ensure!(
        record[8 + frame_len..].iter().all(|byte| *byte == 0),
        "receipt ledger record frame padding non-zero"
    );
    let frame = &record[8..8 + frame_len];
    let decoded = crate::wal::frame::decode_frame(frame)
        .context("receipt ledger record frame does not decode")?;
    anyhow::ensure!(
        decoded.header.total_len as usize == frame_len,
        "receipt ledger record frame trailing bytes"
    );
    anyhow::ensure!(
        decoded.header.event_type == EVENT_TYPE_EXTENDED
            && decoded.header.event_subtype == ExtendedSubtype::ContextEvidenceReceipt as u8,
        "receipt ledger record is not ContextEvidenceReceipt"
    );
    let receipt = ContextEvidenceReceipt::decode(decoded.payload)
        .context("receipt ledger record receipt is not closed")?;
    let handle = receipt.opaque_handle()?;
    Ok((handle, receipt))
}

fn finalize_manifest(manifest: &mut Manifest, key: &[u8; 32]) -> Result<()> {
    anyhow::ensure!(
        manifest.bytes.len() == MANIFEST_BYTES,
        "receipt ledger manifest size mismatch"
    );
    let total: u32 = manifest
        .entries
        .iter()
        .map(|entry| u32::from(entry.count))
        .sum();
    anyhow::ensure!(
        total == manifest.total_records
            && usize::try_from(total)
                .ok()
                .is_some_and(|value| value <= LIFETIME_CAPACITY),
        "receipt ledger manifest total mismatch"
    );
    let bytes = &mut manifest.bytes;
    bytes[..MANIFEST_HEADER_BYTES].fill(0);
    bytes[..8].copy_from_slice(MANIFEST_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[12..20].copy_from_slice(&manifest.generation.to_le_bytes());
    bytes[20..28].copy_from_slice(&manifest.previous_generation.to_le_bytes());
    bytes[28..60].copy_from_slice(&manifest.previous_sha256);
    bytes[60..64].copy_from_slice(&manifest.total_records.to_le_bytes());
    bytes[64..68].copy_from_slice(&(LIFETIME_CAPACITY as u32).to_le_bytes());
    for (index, entry) in manifest.entries.iter().enumerate() {
        let offset = MANIFEST_HEADER_BYTES + index * MANIFEST_ENTRY_BYTES;
        bytes[offset] = u8::from(entry.present);
        bytes[offset + 1] = entry.slot;
        bytes[offset + 2..offset + 4].copy_from_slice(&entry.count.to_le_bytes());
        bytes[offset + 4..offset + 12].copy_from_slice(&entry.generation.to_le_bytes());
        bytes[offset + 12..offset + 44].copy_from_slice(&entry.shard_sha256);
    }
    let tag = tag(key, DOMAIN_FILE, &bytes[..MANIFEST_BYTES - TAG_BYTES]);
    bytes[MANIFEST_BYTES - TAG_BYTES..].copy_from_slice(&tag);
    Ok(())
}

fn parse_manifest(bytes: &[u8], key: &[u8; 32]) -> Result<Manifest> {
    anyhow::ensure!(
        bytes.len() == MANIFEST_BYTES,
        "receipt ledger manifest has non-fixed size"
    );
    verify_tag(key, DOMAIN_FILE, bytes)?;
    anyhow::ensure!(
        &bytes[..8] == MANIFEST_MAGIC,
        "receipt ledger manifest magic mismatch"
    );
    anyhow::ensure!(
        u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == FORMAT_VERSION
            && bytes[10..12].iter().all(|byte| *byte == 0),
        "receipt ledger manifest version/reserved mismatch"
    );
    let generation = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let previous_generation = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    let previous_sha256 = bytes[28..60].try_into().unwrap();
    let total_records = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
    anyhow::ensure!(
        u32::from_le_bytes(bytes[64..68].try_into().unwrap()) == LIFETIME_CAPACITY as u32,
        "receipt ledger manifest capacity mismatch"
    );
    anyhow::ensure!(
        generation > previous_generation || (generation == 1 && previous_generation == 0),
        "receipt ledger manifest generation is invalid"
    );
    if previous_generation == 0 {
        anyhow::ensure!(
            previous_sha256 == ZERO_SHA,
            "receipt ledger genesis manifest has prior digest"
        );
    }
    let mut entries = [ManifestEntry::EMPTY; SHARD_COUNT];
    for (index, entry) in entries.iter_mut().enumerate() {
        let offset = MANIFEST_HEADER_BYTES + index * MANIFEST_ENTRY_BYTES;
        let present = bytes[offset];
        anyhow::ensure!(present <= 1, "receipt ledger manifest present flag invalid");
        let slot = bytes[offset + 1];
        let count = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
        let entry_generation =
            u64::from_le_bytes(bytes[offset + 4..offset + 12].try_into().unwrap());
        let sha = bytes[offset + 12..offset + 44].try_into().unwrap();
        if present == 0 {
            anyhow::ensure!(
                slot == 0 && count == 0 && entry_generation == 0 && sha == ZERO_SHA,
                "receipt ledger absent manifest entry is non-zero"
            );
        } else {
            anyhow::ensure!(
                slot < 2
                    && count > 0
                    && usize::from(count) <= RECORDS_PER_SHARD
                    && entry_generation > 0
                    && entry_generation <= generation
                    && sha != ZERO_SHA,
                "receipt ledger manifest entry invalid"
            );
        }
        *entry = ManifestEntry {
            present: present == 1,
            slot,
            count,
            generation: entry_generation,
            shard_sha256: sha,
        };
    }
    let computed: u32 = entries.iter().map(|entry| u32::from(entry.count)).sum();
    anyhow::ensure!(
        computed == total_records
            && usize::try_from(computed)
                .ok()
                .is_some_and(|value| value <= LIFETIME_CAPACITY),
        "receipt ledger manifest total is invalid"
    );
    Ok(Manifest {
        generation,
        previous_generation,
        previous_sha256,
        total_records,
        entries,
        bytes: bytes.to_vec(),
    })
}

fn serialize_pending(pending: &Pending, key: &[u8; 32]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        pending.manifest.bytes.len() == MANIFEST_BYTES,
        "receipt ledger pending manifest size mismatch"
    );
    anyhow::ensure!(
        sha256(&pending.manifest.bytes) == pending.new_manifest_sha256,
        "receipt ledger pending manifest digest mismatch"
    );
    let mut bytes = vec![0; PENDING_BYTES];
    bytes[..8].copy_from_slice(PENDING_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[12..44].copy_from_slice(&pending.old_manifest_sha256);
    bytes[44..52].copy_from_slice(&pending.new_generation.to_le_bytes());
    bytes[52] = pending.shard;
    bytes[53] = pending.slot;
    bytes[60..92].copy_from_slice(&pending.new_shard_sha256);
    bytes[92..124].copy_from_slice(&pending.new_manifest_sha256);
    bytes[124..128].copy_from_slice(&(MANIFEST_BYTES as u32).to_le_bytes());
    bytes[PENDING_PREFIX_BYTES..PENDING_PREFIX_BYTES + MANIFEST_BYTES]
        .copy_from_slice(&pending.manifest.bytes);
    let tag = tag(key, DOMAIN_FILE, &bytes[..PENDING_BYTES - TAG_BYTES]);
    bytes[PENDING_BYTES - TAG_BYTES..].copy_from_slice(&tag);
    Ok(bytes)
}

fn parse_pending(bytes: &[u8], key: &[u8; 32]) -> Result<Pending> {
    anyhow::ensure!(
        bytes.len() == PENDING_BYTES,
        "receipt ledger pending journal has non-fixed size"
    );
    verify_tag(key, DOMAIN_FILE, bytes)?;
    anyhow::ensure!(
        &bytes[..8] == PENDING_MAGIC
            && u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == FORMAT_VERSION
            && bytes[10..12].iter().all(|byte| *byte == 0),
        "receipt ledger pending journal header invalid"
    );
    anyhow::ensure!(
        bytes[54..60].iter().all(|byte| *byte == 0)
            && u32::from_le_bytes(bytes[124..128].try_into().unwrap()) as usize == MANIFEST_BYTES,
        "receipt ledger pending journal reserved/length invalid"
    );
    let old_manifest_sha256 = bytes[12..44].try_into().unwrap();
    let new_generation = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
    let shard = bytes[52];
    let slot = bytes[53];
    anyhow::ensure!(slot < 2, "receipt ledger pending slot invalid");
    let new_shard_sha256 = bytes[60..92].try_into().unwrap();
    let new_manifest_sha256 = bytes[92..124].try_into().unwrap();
    let manifest = parse_manifest(
        &bytes[PENDING_PREFIX_BYTES..PENDING_PREFIX_BYTES + MANIFEST_BYTES],
        key,
    )?;
    anyhow::ensure!(
        manifest.generation == new_generation && sha256(&manifest.bytes) == new_manifest_sha256,
        "receipt ledger pending embedded manifest mismatch"
    );
    let entry = manifest.entries[shard as usize];
    anyhow::ensure!(
        entry.present
            && entry.slot == slot
            && entry.generation == new_generation
            && entry.shard_sha256 == new_shard_sha256,
        "receipt ledger pending shard binding mismatch"
    );
    Ok(Pending {
        old_manifest_sha256,
        new_generation,
        shard,
        slot,
        new_shard_sha256,
        new_manifest_sha256,
        manifest,
    })
}

fn shard_records(bytes: &[u8]) -> &[u8] {
    &bytes[SHARD_HEADER_BYTES..SHARD_HEADER_BYTES + RECORDS_BYTES]
}

fn shard_records_mut(bytes: &mut [u8]) -> &mut [u8] {
    &mut bytes[SHARD_HEADER_BYTES..SHARD_HEADER_BYTES + RECORDS_BYTES]
}

fn record_at(bytes: &[u8], index: usize) -> Result<&[u8]> {
    anyhow::ensure!(
        index < RECORDS_PER_SHARD,
        "receipt ledger record index out of range"
    );
    let start = SHARD_HEADER_BYTES + index * RECORD_BYTES;
    Ok(&bytes[start..start + RECORD_BYTES])
}

fn tag(key: &[u8; 32], domain: &[u8], body: &[u8]) -> [u8; TAG_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(body);
    mac.finalize().into_bytes().into()
}

fn verify_tag(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() >= TAG_BYTES,
        "receipt ledger authenticated object is too short"
    );
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(&bytes[..bytes.len() - TAG_BYTES]);
    mac.verify_slice(&bytes[bytes.len() - TAG_BYTES..])
        .map_err(|_| anyhow::anyhow!("receipt ledger authentication tag mismatch"))
}

fn shard_for_handle(key: &[u8; 32], handle: &[u8; 32]) -> u8 {
    crate::util::hmac::sha256(key, handle)[0]
}

fn sha256(bytes: &[u8]) -> [u8; SHA_BYTES] {
    Sha256::digest(bytes).into()
}

fn manifest_file_name(generation: u64) -> String {
    format!("manifest-{generation:016x}.v1")
}

fn shard_file_name(shard: u8, slot: u8, generation: u64) -> String {
    format!("shard-{shard:02x}-slot-{slot}-gen-{generation:016x}.v1")
}

fn parse_manifest_name(name: &str) -> Option<u64> {
    let inner = name.strip_prefix("manifest-")?.strip_suffix(".v1")?;
    (inner.len() == 16 && inner.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(inner, 16).ok())
        .flatten()
}

fn parse_shard_name(name: &str) -> Option<(u8, u8, u64)> {
    let body = name.strip_prefix("shard-")?.strip_suffix(".v1")?;
    let (shard, rest) = body.split_once("-slot-")?;
    let (slot, generation) = rest.split_once("-gen-")?;
    let shard = (shard.len() == 2 && shard.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u8::from_str_radix(shard, 16).ok())
        .flatten()?;
    let slot = (slot.len() == 1)
        .then(|| slot.parse::<u8>().ok())
        .flatten()?;
    let generation = (generation.len() == 16
        && generation.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| u64::from_str_radix(generation, 16).ok())
    .flatten()?;
    (slot < 2).then_some((shard, slot, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_path(home: &Path) -> std::path::PathBuf {
        home.join("wal").join(LEDGER_DIR)
    }

    fn anchor_path(home: &Path) -> std::path::PathBuf {
        home.join("wal").join(ANCHOR_DIR)
    }

    fn bounded_namespace_bytes(home: &Path) -> u64 {
        [ledger_path(home), anchor_path(home)]
            .into_iter()
            .filter_map(|directory| std::fs::read_dir(directory).ok())
            .flat_map(|entries| entries.filter_map(std::result::Result::ok))
            .filter_map(|entry| entry.metadata().ok())
            .filter(|metadata| metadata.is_file())
            .fold(0u64, |total, metadata| total.saturating_add(metadata.len()))
    }

    fn namespace_names(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn closed_frame(handle: [u8; 32]) -> (ContextEvidenceReceipt, Vec<u8>) {
        closed_frame_at_revision(handle, 1)
    }

    fn closed_frame_at_revision(
        handle: [u8; 32],
        policy_revision: u64,
    ) -> (ContextEvidenceReceipt, Vec<u8>) {
        let receipt = ContextEvidenceReceipt::new(
            hex::encode(handle),
            crate::wal::events::ContextEvidenceReceiptKind::LocalImport,
            policy_revision,
            2,
            3,
        )
        .unwrap();
        let payload = receipt.encode().unwrap();
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::ContextEvidenceReceipt as u8)
            .build();
        (receipt, crate::wal::frame::encode_frame(&header, &payload))
    }

    #[test]
    fn fixed_layout_and_transaction_bounds_are_exact() {
        assert_eq!(RECORD_BYTES, 368);
        assert_eq!(SHARD_BYTES, 1_507_416);
        assert_eq!(MANIFEST_BYTES, 11_364);
        assert_eq!(PENDING_BYTES, 11_524);
        assert_eq!(
            MAX_TRANSACTION_BYTES,
            (MAX_LEDGER_KEY_FILE_BYTES
                + PENDING_BYTES
                + SHARD_BYTES
                + MANIFEST_BYTES * 2
                + ANCHOR_BYTES * 2) as u64
        );
        assert_eq!(LIFETIME_CAPACITY, 1_048_576);
        assert!(SHARD_COUNT + 4 < MAX_DIRECTORY_ENTRIES);
        assert_eq!(MAX_OPERATION_DIRECTORY_ENTRIES, MAX_DIRECTORY_ENTRIES * 6);
        assert!(MAX_OPERATION_FILE_READS >= 14);
        assert!(MAX_OPERATION_READ_BYTES >= MANIFEST_BYTES * 4 + SHARD_BYTES * 4 + PENDING_BYTES);
    }

    #[test]
    fn generation_names_are_closed_and_bounded() {
        let manifest = manifest_file_name(9);
        assert_eq!(parse_manifest_name(&manifest), Some(9));
        assert_eq!(
            parse_manifest_name("manifest-0000000000000009.v1.bak"),
            None
        );
        let shard = shard_file_name(0xab, 1, 12);
        assert_eq!(parse_shard_name(&shard), Some((0xab, 1, 12)));
        assert_eq!(
            parse_shard_name("shard-ab-slot-2-gen-000000000000000c.v1"),
            None
        );
    }

    #[test]
    fn manifest_rejects_tamper_and_replay_shape() {
        let key = [7; 32];
        let mut manifest = next_manifest(None, 1, 0, 0, 1, [3; 32]).unwrap();
        finalize_manifest(&mut manifest, &key).unwrap();
        assert!(parse_manifest(&manifest.bytes, &key).is_ok());
        let mut tampered = manifest.bytes.clone();
        tampered[64] ^= 1;
        assert!(parse_manifest(&tampered, &key).is_err());
    }

    #[test]
    fn records_hold_an_actual_closed_context_evidence_frame() {
        let key = [11; 32];
        let handle = [9; 32];
        let (receipt, frame) = closed_frame(handle);
        validate_exact_frame(&handle, &receipt, &frame).unwrap();
        let shard_index = shard_for_handle(&key, &handle);
        let mut shard = empty_shard(shard_index, 1);
        insert_record(&mut shard, 0, &handle, &frame).unwrap();
        finalize_shard(&mut shard, &key).unwrap();
        let entry = ManifestEntry {
            present: true,
            slot: 0,
            count: 1,
            generation: 1,
            shard_sha256: sha256(&shard.bytes),
        };
        assert_eq!(
            receipt_at(
                &parse_shard(&shard.bytes, shard_index, entry, &key).unwrap(),
                0
            )
            .unwrap(),
            receipt
        );
        let mut tampered = shard.bytes.clone();
        tampered[SHARD_HEADER_BYTES + 8] ^= 1;
        assert!(parse_shard(&tampered, shard_index, entry, &key).is_err());
    }

    #[test]
    fn capacity_rejects_before_a_persistable_record_is_created() {
        let handle = [1; 32];
        let (_, frame) = closed_frame(handle);
        let mut shard = empty_shard(0, 1);
        shard.count = RECORDS_PER_SHARD;
        shard.handles = vec![[0; 32]; RECORDS_PER_SHARD];
        let before = shard.bytes.clone();
        assert!(ensure_insert_capacity(LIFETIME_CAPACITY as u32, 0).is_err());
        assert_eq!(shard.bytes, before);
        assert!(ensure_insert_capacity(0, RECORDS_PER_SHARD).is_err());
        assert!(insert_record(&mut shard, 0, &handle, &frame).is_err());
    }

    #[test]
    fn fresh_append_restart_duplicate_and_collision_are_exact() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let handle = [0x31; 32];
        let (receipt, frame) = closed_frame(handle);
        let first = append_once(home.path(), &handle, &receipt, &frame).unwrap();
        assert_eq!(first.decision(), AppendDecision::Appended);
        assert_eq!(first.reclaimed_bytes(), 0);
        assert_eq!(first.replacement_bytes(), 0);
        assert_eq!(first.retained_bytes(), bounded_namespace_bytes(home.path()));
        assert!(first.retained_bytes() <= MAX_TRANSACTION_BYTES);

        let stable_bytes = bounded_namespace_bytes(home.path());
        let duplicate = append_once(home.path(), &handle, &receipt, &frame).unwrap();
        assert_eq!(duplicate.decision(), AppendDecision::AlreadyPresent);
        assert_eq!(duplicate.retained_bytes(), 0);
        assert_eq!(duplicate.reclaimed_bytes(), 0);
        assert_eq!(bounded_namespace_bytes(home.path()), stable_bytes);
        assert!(contains_for_test(home.path(), &handle, &receipt).unwrap());

        let (conflict, conflict_frame) = closed_frame_at_revision(handle, 9);
        let error = append_once(home.path(), &handle, &conflict, &conflict_frame).unwrap_err();
        assert_eq!(error.retained_bytes(), 0);
        assert_eq!(error.reclaimed_bytes(), 0);
        assert_eq!(bounded_namespace_bytes(home.path()), stable_bytes);
    }

    #[test]
    fn production_reader_authenticates_head_exact_receipt_and_absence() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        assert!(
            read_authenticated_ledger(home.path(), None)
                .unwrap()
                .is_none()
        );

        let handle = [0x32; 32];
        let (receipt, frame) = closed_frame(handle);
        append_once(home.path(), &handle, &receipt, &frame).unwrap();

        let view = read_authenticated_ledger(home.path(), Some(&handle))
            .unwrap()
            .unwrap();
        assert_eq!(view.head.schema_version, FORMAT_VERSION);
        assert_eq!(view.head.total_records, 1);
        let record = view.receipt.unwrap();
        assert_eq!(record.receipt, receipt);
        assert_eq!(record.exact_frame_sha256, hex::encode(sha256(&frame)));
        assert_eq!(record.exact_frame_hex, hex::encode(&frame));

        let absent = [0x33; 32];
        let view = read_authenticated_ledger(home.path(), Some(&absent))
            .unwrap()
            .unwrap();
        assert!(view.receipt.is_none());

        fail_transaction_after_for_test(home.path(), TestTransactionFailure::AfterPending);
        let next_handle = [0x34; 32];
        let (next, next_frame) = closed_frame(next_handle);
        append_once(home.path(), &next_handle, &next, &next_frame).unwrap_err();
        assert!(read_authenticated_ledger(home.path(), None).is_err());
    }

    #[test]
    fn every_durable_transaction_boundary_recovers_without_a_second_receipt() {
        let cases = [
            (TestTransactionFailure::AfterKey, AppendDecision::Appended),
            (
                TestTransactionFailure::AfterPending,
                AppendDecision::Appended,
            ),
            (
                TestTransactionFailure::AfterShard,
                AppendDecision::AlreadyPresent,
            ),
            (
                TestTransactionFailure::AfterManifest,
                AppendDecision::AlreadyPresent,
            ),
            (
                TestTransactionFailure::AfterAnchor,
                AppendDecision::AlreadyPresent,
            ),
            (
                TestTransactionFailure::AfterPendingRemoval,
                AppendDecision::AlreadyPresent,
            ),
        ];
        for (index, (phase, expected_decision)) in cases.into_iter().enumerate() {
            let home = crate::test_env::canonical_tempdir().unwrap();
            let handle = [u8::try_from(index + 1).unwrap(); 32];
            let (receipt, frame) = closed_frame(handle);
            fail_transaction_after_for_test(home.path(), phase);
            let first = append_once(home.path(), &handle, &receipt, &frame).unwrap_err();
            assert!(first.retained_bytes() <= MAX_TRANSACTION_BYTES);
            let recovered = append_once(home.path(), &handle, &receipt, &frame).unwrap();
            assert_eq!(recovered.decision(), expected_decision, "phase {phase:?}");
            assert!(contains_for_test(home.path(), &handle, &receipt).unwrap());
            let after_recovery = bounded_namespace_bytes(home.path());
            let duplicate = append_once(home.path(), &handle, &receipt, &frame).unwrap();
            assert_eq!(duplicate.decision(), AppendDecision::AlreadyPresent);
            assert_eq!(bounded_namespace_bytes(home.path()), after_recovery);
        }
    }

    #[test]
    fn repeated_failure_recovery_replaces_only_exact_receipt_debt() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let handle = [0x39; 32];
        let (receipt, frame) = closed_frame(handle);
        let mut debt = ReceiptQuotaDebt::default();

        fail_transaction_after_for_test(home.path(), TestTransactionFailure::AfterPending);
        let first = append_once_with_quota_debt(home.path(), &handle, &receipt, &frame, &mut debt)
            .unwrap_err();
        assert!(first.retained_bytes() >= PENDING_BYTES as u64);
        assert_eq!(first.reclaimed_debt_bytes(), 0);

        fail_transaction_after_for_test(home.path(), TestTransactionFailure::AfterPending);
        let second = append_once_with_quota_debt(home.path(), &handle, &receipt, &frame, &mut debt)
            .unwrap_err();
        assert_eq!(second.reclaimed_debt_bytes(), PENDING_BYTES as u64);
        assert_eq!(second.retained_bytes(), PENDING_BYTES as u64);

        let recovered =
            append_once_with_quota_debt(home.path(), &handle, &receipt, &frame, &mut debt).unwrap();
        assert_eq!(recovered.decision(), AppendDecision::Appended);
        assert_eq!(recovered.reclaimed_debt_bytes(), PENDING_BYTES as u64);
        assert!(recovered.replacement_bytes() <= recovered.reclaimed_bytes());
        assert!(contains_for_test(home.path(), &handle, &receipt).unwrap());
    }

    #[test]
    fn publication_plus_cleanup_failures_never_undercharge_retained_objects() {
        let cases = [
            (TestCanonicalObject::Key, MAX_LEDGER_KEY_FILE_BYTES as u64),
            (TestCanonicalObject::Pending, PENDING_BYTES as u64),
            (TestCanonicalObject::Shard, SHARD_BYTES as u64),
            (TestCanonicalObject::Manifest, MANIFEST_BYTES as u64),
            (TestCanonicalObject::Anchor, ANCHOR_BYTES as u64),
        ];
        for (index, (object, object_maximum)) in cases.into_iter().enumerate() {
            let home = crate::test_env::canonical_tempdir().unwrap();
            let handle = [u8::try_from(index + 0x41).unwrap(); 32];
            let (receipt, frame) = closed_frame(handle);
            let parent = if object == TestCanonicalObject::Anchor {
                anchor_path(home.path())
            } else {
                ledger_path(home.path())
            };
            fail_canonical_write_for_test(
                &parent,
                object,
                TestCanonicalWriteFailure::AfterFileSync,
            );
            fail_canonical_write_for_test(
                &parent,
                object,
                TestCanonicalWriteFailure::RollbackRemove,
            );
            let error = append_once(home.path(), &handle, &receipt, &frame).unwrap_err();
            assert!(
                error.retained_bytes() >= object_maximum,
                "object {object:?}"
            );
            assert!(error.retained_bytes() <= MAX_TRANSACTION_BYTES);
            assert!(bounded_namespace_bytes(home.path()) <= error.retained_bytes());

            let recovered = append_once(home.path(), &handle, &receipt, &frame).unwrap();
            assert!(matches!(
                recovered.decision(),
                AppendDecision::Appended | AppendDecision::AlreadyPresent
            ));
            assert!(contains_for_test(home.path(), &handle, &receipt).unwrap());
            let stable = bounded_namespace_bytes(home.path());
            let duplicate = append_once(home.path(), &handle, &receipt, &frame).unwrap();
            assert_eq!(duplicate.decision(), AppendDecision::AlreadyPresent);
            assert_eq!(bounded_namespace_bytes(home.path()), stable);
        }
    }

    #[test]
    fn rollback_parent_sync_failure_stays_conservatively_charged() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let handle = [0x71; 32];
        let (receipt, frame) = closed_frame(handle);
        let parent = ledger_path(home.path());
        fail_canonical_write_for_test(
            &parent,
            TestCanonicalObject::Key,
            TestCanonicalWriteFailure::AfterFileSync,
        );
        fail_canonical_write_for_test(
            &parent,
            TestCanonicalObject::Key,
            TestCanonicalWriteFailure::RollbackParentSync,
        );
        let error = append_once(home.path(), &handle, &receipt, &frame).unwrap_err();
        assert_eq!(error.retained_bytes(), MAX_LEDGER_KEY_FILE_BYTES as u64);
        assert!(error.retained_bytes() <= MAX_TRANSACTION_BYTES);
    }

    #[test]
    fn authenticated_old_new_pending_pair_is_the_only_two_manifest_recovery() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let first_handle = [0x81; 32];
        let (first, first_frame) = closed_frame(first_handle);
        append_once(home.path(), &first_handle, &first, &first_frame).unwrap();

        let second_handle = [0x82; 32];
        let (second, second_frame) = closed_frame(second_handle);
        fail_transaction_after_for_test(home.path(), TestTransactionFailure::AfterManifest);
        append_once(home.path(), &second_handle, &second, &second_frame).unwrap_err();
        let before = namespace_names(&ledger_path(home.path()));
        assert_eq!(
            before
                .iter()
                .filter(|name| parse_manifest_name(name).is_some())
                .count(),
            2
        );
        assert!(before.iter().any(|name| name == PENDING));

        let recovered = append_once(home.path(), &second_handle, &second, &second_frame).unwrap();
        assert_eq!(recovered.decision(), AppendDecision::AlreadyPresent);
        let after = namespace_names(&ledger_path(home.path()));
        assert_eq!(
            after
                .iter()
                .filter(|name| parse_manifest_name(name).is_some())
                .count(),
            1
        );
        assert!(!after.iter().any(|name| name == PENDING));

        let active_manifest = after
            .iter()
            .find(|name| parse_manifest_name(name).is_some())
            .unwrap();
        let forged_third = manifest_file_name(0xffff);
        std::fs::copy(
            ledger_path(home.path()).join(active_manifest),
            ledger_path(home.path()).join(forged_third),
        )
        .unwrap();
        assert!(append_once(home.path(), &second_handle, &second, &second_frame).is_err());
    }

    #[test]
    fn missing_or_successor_anchor_blocks_selective_ledger_rollback() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let first_handle = [0x91; 32];
        let (first, first_frame) = closed_frame(first_handle);
        append_once(home.path(), &first_handle, &first, &first_frame).unwrap();
        let old_names = namespace_names(&ledger_path(home.path()));
        let old_manifest_name = old_names
            .iter()
            .find(|name| parse_manifest_name(name).is_some())
            .unwrap()
            .clone();
        let old_shard_name = old_names
            .iter()
            .find(|name| parse_shard_name(name).is_some())
            .unwrap()
            .clone();
        let old_manifest =
            std::fs::read(ledger_path(home.path()).join(&old_manifest_name)).unwrap();
        let old_shard = std::fs::read(ledger_path(home.path()).join(&old_shard_name)).unwrap();

        let second_handle = [0x92; 32];
        let (second, second_frame) = closed_frame(second_handle);
        append_once(home.path(), &second_handle, &second, &second_frame).unwrap();
        for name in namespace_names(&ledger_path(home.path())) {
            if parse_manifest_name(&name).is_some() || parse_shard_name(&name).is_some() {
                std::fs::remove_file(ledger_path(home.path()).join(name)).unwrap();
            }
        }
        std::fs::write(
            ledger_path(home.path()).join(old_manifest_name),
            old_manifest,
        )
        .unwrap();
        std::fs::write(ledger_path(home.path()).join(old_shard_name), old_shard).unwrap();
        assert!(append_once(home.path(), &first_handle, &first, &first_frame).is_err());

        let fresh = crate::test_env::canonical_tempdir().unwrap();
        let handle = [0x93; 32];
        let (receipt, frame) = closed_frame(handle);
        append_once(fresh.path(), &handle, &receipt, &frame).unwrap();
        for name in namespace_names(&anchor_path(fresh.path())) {
            std::fs::remove_file(anchor_path(fresh.path()).join(name)).unwrap();
        }
        assert!(append_once(fresh.path(), &handle, &receipt, &frame).is_err());
    }

    #[test]
    fn replaced_key_and_replayed_shard_fail_closed() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let handle = [0xa1; 32];
        let (receipt, frame) = closed_frame(handle);
        append_once(home.path(), &handle, &receipt, &frame).unwrap();
        let key_path = ledger_path(home.path()).join(LEDGER_KEY);
        let replacement =
            crate::wal::compaction::encode_key_for_storage(&key_path, &[0x55; 32]).unwrap();
        std::fs::write(&key_path, replacement).unwrap();
        assert!(append_once(home.path(), &handle, &receipt, &frame).is_err());

        let replay = crate::test_env::canonical_tempdir().unwrap();
        let first_handle = [0xa2; 32];
        let (first, first_frame) = closed_frame(first_handle);
        append_once(replay.path(), &first_handle, &first, &first_frame).unwrap();
        let first_shard_name = namespace_names(&ledger_path(replay.path()))
            .into_iter()
            .find(|name| parse_shard_name(name).is_some())
            .unwrap();
        let stale_shard =
            std::fs::read(ledger_path(replay.path()).join(&first_shard_name)).unwrap();
        let key_display = ledger_path(replay.path()).join(LEDGER_KEY);
        let key: [u8; 32] = crate::wal::compaction::maybe_unwrap_dpapi(
            &std::fs::read(&key_display).unwrap(),
            &key_display,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let target_shard = shard_for_handle(&key, &first_handle);
        let second_handle = (0u16..=u16::MAX)
            .map(|value| {
                let mut candidate = [0u8; 32];
                candidate[..2].copy_from_slice(&value.to_le_bytes());
                candidate
            })
            .find(|candidate| {
                *candidate != first_handle && shard_for_handle(&key, candidate) == target_shard
            })
            .unwrap();
        let (second, second_frame) = closed_frame(second_handle);
        append_once(replay.path(), &second_handle, &second, &second_frame).unwrap();
        let current_shard_name = namespace_names(&ledger_path(replay.path()))
            .into_iter()
            .find(|name| parse_shard_name(name).is_some())
            .unwrap();
        std::fs::write(
            ledger_path(replay.path()).join(current_shard_name),
            stale_shard,
        )
        .unwrap();
        assert!(append_once(replay.path(), &second_handle, &second, &second_frame).is_err());
    }

    #[test]
    fn legacy_primary_wal_receipts_are_never_an_admission_fallback() {
        assert!(LEDGER_V1_IS_FIRST_CONTEXT_EVIDENCE_RECEIPT_PRODUCER);
        // The production append path accepts only the exact ledger frame and
        // contains no call to the O(history) offline scanner.  A historical
        // primary-WAL 0x27 discovered by explicit forensic tooling therefore
        // requires a stopped-daemon authenticated migration; it cannot turn a
        // ledger absence into a runtime ACK.
        let source = include_str!("context_evidence_receipts.rs");
        assert!(!source.contains("authenticated_context_evidence_receipt_exists("));
    }
}
