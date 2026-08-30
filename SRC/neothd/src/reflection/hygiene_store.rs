//! Private, versioned persistence for the reflection-hygiene planner.
//!
//! This module deliberately has no scheduler, CLI, GUI, Buddy, Obsidian, or
//! yearly-materialisation side effects. It validates a complete candidate in
//! memory, then replaces one authoritative private snapshot atomically.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::hygiene::{
    HYGIENE_PLAN_SCHEMA_VERSION, HygieneError, HygienePlan, LegacyHygieneInput, RawReflection,
    TopicSynonymMap, VersionedHygieneInput, plan_legacy, plan_versioned,
};
use super::periodic::PeriodReflection;

/// Name of the only authoritative V1 hygiene snapshot.
pub const HYGIENE_STATE_FILE: &str = "state-v1.json";
/// Read-only legacy artifact eligible for a single explicit import.
pub const LEGACY_HYGIENE_STATE_FILE: &str = "state.json";

/// Tight upper bounds keep a corrupt private file from becoming an allocation
/// or planner-amplification source.
pub const MAX_HYGIENE_SNAPSHOT_BYTES: usize = 256 * 1024;
pub const MAX_HYGIENE_RAW_REFLECTIONS: usize = 1_024;
pub const MAX_HYGIENE_PERIOD_REFLECTIONS: usize = 1_024;
pub const MAX_HYGIENE_SYNONYMS: usize = 1_024;
pub const MAX_HYGIENE_TOPICS_PER_REFLECTION: usize = 64;
pub const MAX_HYGIENE_ID_BYTES: usize = 256;
pub const MAX_HYGIENE_TAG_BYTES: usize = 64;
pub const MAX_HYGIENE_TOPIC_BYTES: usize = 512;
pub const MAX_HYGIENE_BODY_BYTES: usize = 64 * 1024;
/// Sum of every candidate string kept by this store before it clones planner
/// input. This remains at or below the bounded snapshot size.
pub const MAX_HYGIENE_IN_MEMORY_INPUT_BYTES: usize = MAX_HYGIENE_SNAPSHOT_BYTES;

// Advisory file-lock reentrancy differs across platforms. This guard provides
// same-process serialization; the capability-bound file lock remains the
// authority across processes.
static HYGIENE_STATE_LOCK: Mutex<()> = Mutex::new(());
static DAILY_ADMISSION_STATE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
static TEST_DAILY_ADMISSION_STALE_CAS: Mutex<std::collections::BTreeSet<PathBuf>> =
    Mutex::new(std::collections::BTreeSet::new());

/// State-free, test-only authority for one synthetic stale Daily-admission
/// CAS. The exact private home is the scope: it permits a test to hand the
/// fault to a worker thread without allowing a concurrently scheduled test on
/// another home to consume it. Production admission never observes this map.
#[cfg(test)]
#[must_use]
pub(crate) struct DailyAdmissionStaleCasTestScope {
    home: PathBuf,
}

#[cfg(test)]
impl Drop for DailyAdmissionStaleCasTestScope {
    fn drop(&mut self) {
        let mut pending = TEST_DAILY_ADMISSION_STALE_CAS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.remove(&self.home);
    }
}

/// Test-only fault injection: model a competing writer winning between the
/// caller's admission read and CAS without exposing any production seam.
#[cfg(test)]
pub(crate) fn fail_next_daily_admission_cas_as_stale_for_test(
    neoth_home: &Path,
) -> DailyAdmissionStaleCasTestScope {
    let home = neoth_home.to_path_buf();
    let already_armed = {
        let mut pending = TEST_DAILY_ADMISSION_STALE_CAS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !pending.insert(home.clone())
    };
    assert!(
        !already_armed,
        "daily-admission stale-CAS test fault is already armed for this home"
    );
    DailyAdmissionStaleCasTestScope { home }
}

pub const DAILY_ADMISSION_STATE_FILE: &str = "state-v1.json";
/// Version 2 deliberately requires the cryptographic archive digest. Version
/// 1 carried a non-cryptographic fingerprint and is fail-closed rather than
/// silently accepted as recovery authority.
pub const DAILY_ADMISSION_STATE_SCHEMA_VERSION: u16 = 2;
/// SHA-256 is stored as exactly sixty-four lower-case hexadecimal bytes.
pub const DAILY_ADMISSION_ARCHIVE_SHA256_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DailyAdmissionOutcome {
    Admitted,
    Suppressed,
}

/// This state belongs only to the opt-in daily admission gate.  It does not
/// share a revision, a namespace, or retention semantics with hygiene state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DailyAdmissionState {
    pub schema_version: u16,
    pub revision: u64,
    pub tag: String,
    pub outcome: DailyAdmissionOutcome,
    /// Stable SHA-256 of the exact admitted JSONL record. Suppression has
    /// no archive and therefore no digest. This prevents a later same-tag
    /// candidate from changing what recovery publishes to Obsidian.
    pub archive_sha256: Option<String>,
}

pub struct DailyAdmissionGuard {
    process_lock: Option<std::sync::MutexGuard<'static, ()>>,
    store: crate::skills::store::BoundDirectory,
    os_lock: Option<std::fs::File>,
    lock_binding: Option<crate::skills::store::BoundChildObject>,
    #[cfg(test)]
    test_home: PathBuf,
}

/// The durable snapshot. Its raw set is always the retained set of a freshly
/// computed plan; historical period records and the operator's exact synonym
/// spellings are stored without projection.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HygieneState {
    pub schema_version: u16,
    pub revision: u64,
    #[serde(deserialize_with = "deserialize_raw_reflections_strict")]
    pub raw_reflections: Vec<RawReflection>,
    #[serde(deserialize_with = "deserialize_period_reflections_strict")]
    pub period_reflections: Vec<PeriodReflection>,
    pub topic_synonyms: TopicSynonymMap,
}

/// Visible result of an optimistic revision-CAS apply.
#[derive(Clone, PartialEq, Eq)]
pub struct HygieneApplyOutcome {
    pub state: HygieneState,
    pub plan: HygienePlan,
    /// `false` means an identical retained snapshot already existed and no
    /// replacement or revision increment was performed.
    pub written: bool,
    /// A published-but-unconfirmed commit must be recovered by a fresh bound
    /// read, never retried as though no state change happened.
    pub durability: HygieneDurability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HygieneDurability {
    Confirmed,
    RecoveryReadRequired,
}

/// Result of an explicit legacy import attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HygieneMigrationOutcome {
    NoLegacyArtifact,
    Migrated(Box<HygieneApplyOutcome>),
}

/// Fail-closed storage errors. Every error exits before any snapshot write.
pub enum HygieneStoreError {
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    InvalidSnapshot(serde_json::Error),
    InvalidPlan(HygieneError),
    UnsupportedSnapshotVersion {
        found: u16,
    },
    InvalidSnapshotRevision {
        found: u64,
    },
    LegacyMigrationRequired,
    LockPoisoned,
    LockUnavailable,
    SafeStoreUnavailable,
    CapacityExceeded,
    DurabilityUnknown,
    StaleRevision {
        expected: u64,
        actual: u64,
    },
    StateAlreadyExists,
}

impl std::fmt::Debug for HygieneState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HygieneState")
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("raw_reflection_count", &self.raw_reflections.len())
            .field("period_reflection_count", &self.period_reflections.len())
            .field("topic_synonym_count", &self.topic_synonyms.entries.len())
            .finish()
    }
}

impl std::fmt::Debug for HygieneApplyOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HygieneApplyOutcome")
            .field("state", &self.state)
            .field("plan", &"<redacted>")
            .field("written", &self.written)
            .field("durability", &self.durability)
            .finish()
    }
}

impl std::fmt::Debug for HygieneStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Io { .. } => "Io",
            Self::InvalidSnapshot(_) => "InvalidSnapshot",
            Self::InvalidPlan(_) => "InvalidPlan",
            Self::UnsupportedSnapshotVersion { .. } => "UnsupportedSnapshotVersion",
            Self::InvalidSnapshotRevision { .. } => "InvalidSnapshotRevision",
            Self::LegacyMigrationRequired => "LegacyMigrationRequired",
            Self::LockPoisoned => "LockPoisoned",
            Self::LockUnavailable => "LockUnavailable",
            Self::SafeStoreUnavailable => "SafeStoreUnavailable",
            Self::CapacityExceeded => "CapacityExceeded",
            Self::DurabilityUnknown => "DurabilityUnknown",
            Self::StaleRevision { .. } => "StaleRevision",
            Self::StateAlreadyExists => "StateAlreadyExists",
        };
        formatter
            .debug_struct("HygieneStoreError")
            .field("kind", &kind)
            .finish()
    }
}

impl std::fmt::Display for HygieneStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { action, .. } => write!(formatter, "hygiene state {action} failed"),
            Self::InvalidSnapshot(_) => write!(formatter, "invalid hygiene snapshot"),
            Self::InvalidPlan(_) => write!(formatter, "invalid hygiene plan"),
            Self::UnsupportedSnapshotVersion { found } => {
                write!(formatter, "unsupported hygiene snapshot version {found}")
            }
            Self::InvalidSnapshotRevision { found } => {
                write!(formatter, "invalid hygiene snapshot revision {found}")
            }
            Self::LegacyMigrationRequired => {
                write!(
                    formatter,
                    "legacy hygiene state requires explicit migration"
                )
            }
            Self::LockPoisoned => write!(formatter, "hygiene state lock is poisoned"),
            Self::LockUnavailable => write!(formatter, "hygiene state lock is unavailable"),
            Self::SafeStoreUnavailable => {
                write!(formatter, "safe hygiene state storage is unavailable")
            }
            Self::CapacityExceeded => write!(formatter, "hygiene state exceeds a safety limit"),
            Self::DurabilityUnknown => {
                write!(
                    formatter,
                    "hygiene state may be published but durability is unknown"
                )
            }
            Self::StaleRevision { expected, actual } => write!(
                formatter,
                "stale hygiene snapshot revision: expected {expected}, found {actual}"
            ),
            Self::StateAlreadyExists => write!(formatter, "hygiene V1 snapshot already exists"),
        }
    }
}

impl std::error::Error for HygieneStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// `<neoth-home>/reflections/hygiene/state-v1.json`.
pub fn hygiene_state_path(neoth_home: &Path) -> PathBuf {
    neoth_home
        .join("reflections")
        .join("hygiene")
        .join(HYGIENE_STATE_FILE)
}

/// `<neoth-home>/reflections/hygiene/state.json`, retained after migration.
pub fn legacy_hygiene_state_path(neoth_home: &Path) -> PathBuf {
    neoth_home
        .join("reflections")
        .join("hygiene")
        .join(LEGACY_HYGIENE_STATE_FILE)
}

/// Deterministic per-home cross-process lock beside the authoritative state.
pub fn hygiene_state_lock_path(neoth_home: &Path) -> PathBuf {
    neoth_home
        .join("reflections")
        .join("hygiene")
        .join("state-v1.lock")
}

pub fn daily_admission_state_path(neoth_home: &Path) -> PathBuf {
    neoth_home
        .join("reflections")
        .join("daily-admission")
        .join(DAILY_ADMISSION_STATE_FILE)
}

/// Acquire the one daily-admission gate in process-before-OS-lock order.  The
/// returned guard intentionally spans archive inspection, append/recovery,
/// state CAS, and marker publication so two daemons cannot interleave them.
pub fn lock_daily_admission(neoth_home: &Path) -> Result<DailyAdmissionGuard, HygieneStoreError> {
    // This mutex carries no state; it is only same-process serialization
    // ahead of the authenticated file lock. A panic while it is held cannot
    // corrupt durable admission state, which remains protected by the OS
    // lock and validated private snapshot below. Do not map poison to a
    // persistent availability outage for every later Daily operation.
    let process_lock = DAILY_ADMISSION_STATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    prepare_daily_admission_namespace(neoth_home)?;
    let store = open_daily_admission_directory(neoth_home)?;
    let (os_lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &store.dir,
        OsStr::new("state-v1.lock"),
        &store.display_path.join("state-v1.lock"),
    )
    .map_err(|_| HygieneStoreError::LockUnavailable)?;
    acquire_bound_lock(&os_lock)?;
    Ok(DailyAdmissionGuard {
        process_lock: Some(process_lock),
        store,
        os_lock: Some(os_lock),
        lock_binding: Some(lock_binding),
        #[cfg(test)]
        test_home: neoth_home.to_path_buf(),
    })
}

impl Drop for DailyAdmissionGuard {
    fn drop(&mut self) {
        drop(self.release_os_lock_resources());
        // This is deliberately last. `release_os_lock_resources` consumes and
        // destroys both native lockfile handles even when explicit unlock
        // reports an error, so another same-process contender cannot pass the
        // mutex while either old handle is still alive.
        drop(self.process_lock.take());
    }
}

/// Safely migrate the historical public-ish daily namespace before any daily
/// gate is acquired. Every component is opened through a retained capability;
/// wrong ownership, symlinks, junctions/reparse points, or a failed post-write
/// verification remain hard failures. Only the current owner may have an old
/// `0755`/permissive DACL tightened to the private form.
pub fn prepare_daily_admission_namespace(neoth_home: &Path) -> Result<(), HygieneStoreError> {
    let home = crate::skills::store::open_absolute_bound_directory(
        neoth_home,
        false,
        "daily admission home",
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?
    .ok_or(HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&home.dir)?;
    let reflections_path = neoth_home.join("reflections");
    let reflections = crate::skills::store::open_or_create_private_child_dir(
        &home.dir,
        OsStr::new("reflections"),
        &reflections_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    tighten_legacy_private_directory(&reflections_path, &reflections)?;
    let daily_path = reflections_path.join("daily");
    let daily = crate::skills::store::open_or_create_private_child_dir(
        &reflections,
        OsStr::new("daily"),
        &daily_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    tighten_legacy_private_directory(&daily_path, &daily)
}

impl DailyAdmissionGuard {
    fn release_os_lock_resources(&mut self) -> Option<std::io::Result<()>> {
        let unlock = self.os_lock.as_ref().map(std::fs::File::unlock);
        // `lock_binding` retains a duplicate native identity handle. Destroy
        // it before the locked File and both before `process_lock`; an unlock
        // error therefore changes no teardown ordering assumption.
        drop(self.lock_binding.take());
        drop(self.os_lock.take());
        unlock
    }

    pub fn load(&self) -> Result<Option<DailyAdmissionState>, HygieneStoreError> {
        self.ensure_lock()?;
        let Some(bytes) = read_child_optional(&self.store, DAILY_ADMISSION_STATE_FILE)? else {
            return Ok(None);
        };
        let state: DailyAdmissionState =
            serde_json::from_slice(&bytes).map_err(HygieneStoreError::InvalidSnapshot)?;
        if state.schema_version != DAILY_ADMISSION_STATE_SCHEMA_VERSION {
            return Err(HygieneStoreError::UnsupportedSnapshotVersion {
                found: state.schema_version,
            });
        }
        if state.revision == 0
            || state.tag.is_empty()
            || state.tag.len() > MAX_HYGIENE_TAG_BYTES
            || (state.outcome == DailyAdmissionOutcome::Admitted
                && !state
                    .archive_sha256
                    .as_deref()
                    .is_some_and(valid_daily_archive_sha256))
            || (state.outcome == DailyAdmissionOutcome::Suppressed
                && state.archive_sha256.is_some())
        {
            return Err(HygieneStoreError::InvalidSnapshotRevision {
                found: state.revision,
            });
        }
        Ok(Some(state))
    }

    /// Revision CAS.  `RecoveryReadRequired` means bytes may be published but
    /// their fsync result is unknown; callers must stop before their marker and
    /// recover by a fresh read on the next tick.
    pub fn compare_and_set(
        &self,
        expected_revision: u64,
        tag: &str,
        outcome: DailyAdmissionOutcome,
        archive_sha256: Option<&str>,
    ) -> Result<HygieneDurability, HygieneStoreError> {
        if tag.is_empty() || tag.len() > MAX_HYGIENE_TAG_BYTES {
            return Err(HygieneStoreError::CapacityExceeded);
        }
        if matches!(outcome, DailyAdmissionOutcome::Admitted)
            != archive_sha256.is_some_and(valid_daily_archive_sha256)
        {
            return Err(HygieneStoreError::CapacityExceeded);
        }
        self.ensure_lock()?;
        #[cfg(test)]
        {
            let injected = TEST_DAILY_ADMISSION_STALE_CAS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.test_home);
            if injected {
                return Err(HygieneStoreError::StaleRevision {
                    expected: expected_revision,
                    actual: expected_revision.saturating_add(1),
                });
            }
        }
        let current = self.load()?;
        let actual = current.as_ref().map_or(0, |state| state.revision);
        if actual != expected_revision {
            return Err(HygieneStoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let state = DailyAdmissionState {
            schema_version: DAILY_ADMISSION_STATE_SCHEMA_VERSION,
            revision: actual
                .checked_add(1)
                .ok_or(HygieneStoreError::StaleRevision {
                    expected: expected_revision,
                    actual,
                })?,
            tag: tag.to_string(),
            outcome,
            archive_sha256: archive_sha256.map(str::to_owned),
        };
        let bytes = serde_json::to_vec(&state).map_err(HygieneStoreError::InvalidSnapshot)?;
        match crate::skills::store::atomic_write_private_child_reported(
            &self.store.dir,
            OsStr::new(DAILY_ADMISSION_STATE_FILE),
            &self.store.display_path.join(DAILY_ADMISSION_STATE_FILE),
            &bytes,
        ) {
            Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
                Ok(HygieneDurability::Confirmed)
            }
            Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
                Ok(HygieneDurability::RecoveryReadRequired)
            }
            Err(_) => Err(HygieneStoreError::SafeStoreUnavailable),
        }
    }

    fn ensure_lock(&self) -> Result<(), HygieneStoreError> {
        let lock_binding = self
            .lock_binding
            .as_ref()
            .ok_or(HygieneStoreError::LockUnavailable)?;
        if lock_binding
            .matches_regular_file_child_readonly(
                &self.store.dir,
                OsStr::new("state-v1.lock"),
                &self.store.display_path.join("state-v1.lock"),
            )
            .map_err(|_| HygieneStoreError::LockUnavailable)?
        {
            Ok(())
        } else {
            Err(HygieneStoreError::LockUnavailable)
        }
    }
}

fn valid_daily_archive_sha256(value: &str) -> bool {
    value.len() == DAILY_ADMISSION_ARCHIVE_SHA256_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Loads and structurally validates the authoritative snapshot. Missing state
/// is distinct from corrupt state; callers must never silently treat the
/// latter as a clean first run.
pub fn load_hygiene_state(neoth_home: &Path) -> Result<Option<HygieneState>, HygieneStoreError> {
    let (_process_lock, store, _os_lock, lock_binding) = lock_state(neoth_home)?;
    ensure_lock_binding(&store, &lock_binding)?;
    read_state_at(&store)
}

/// Recomputes the versioned plan and applies its retained raw set iff the
/// current durable revision is `expected_revision`. Candidate period records
/// and synonyms are retained exactly, including non-canonical spelling.
pub fn apply_hygiene_plan(
    neoth_home: &Path,
    expected_revision: u64,
    input: VersionedHygieneInput,
) -> Result<HygieneApplyOutcome, HygieneStoreError> {
    let (_process_lock, store, _os_lock, lock_binding) = lock_state(neoth_home)?;
    ensure_lock_binding(&store, &lock_binding)?;
    let current = read_state_at(&store)?;

    if current.is_none() && read_child_optional(&store, LEGACY_HYGIENE_STATE_FILE)?.is_some() {
        return Err(HygieneStoreError::LegacyMigrationRequired);
    }
    validate_input_bounds(&input)?;
    let plan = plan_versioned(input.clone()).map_err(HygieneStoreError::InvalidPlan)?;

    if let Some(state) = &current {
        // Refuse to replace a syntactically valid-but-semantic-corrupt state.
        // `now_unix` is supplied by the caller's candidate, never persisted.
        validate_existing_state(state, input.now_unix)?;
    }

    let actual_revision = current.as_ref().map_or(0, |state| state.revision);
    if expected_revision != actual_revision {
        return Err(HygieneStoreError::StaleRevision {
            expected: expected_revision,
            actual: actual_revision,
        });
    }

    let retained_state = HygieneState {
        schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
        revision: actual_revision,
        raw_reflections: plan.retained_raw.clone(),
        period_reflections: input.period_reflections,
        topic_synonyms: input.topic_synonyms,
    };
    if current.as_ref() == Some(&retained_state) {
        return Ok(HygieneApplyOutcome {
            state: retained_state,
            plan,
            written: false,
            durability: HygieneDurability::Confirmed,
        });
    }

    let revision = actual_revision
        .checked_add(1)
        .ok_or(HygieneStoreError::StaleRevision {
            expected: expected_revision,
            actual: actual_revision,
        })?;
    let state = HygieneState {
        revision,
        ..retained_state
    };
    ensure_lock_binding(&store, &lock_binding)?;
    let durability = write_state_at(&store, &state)?;
    Ok(HygieneApplyOutcome {
        state,
        plan,
        written: true,
        durability,
    })
}

/// Imports one validated pre-versioned artifact without deleting or changing
/// it. A V1 target is created with `create_new`, so an existing snapshot is
/// never overwritten even if another writer appears after the initial check.
pub fn migrate_legacy_hygiene_state(
    neoth_home: &Path,
) -> Result<HygieneMigrationOutcome, HygieneStoreError> {
    let (_process_lock, store, _os_lock, lock_binding) = lock_state(neoth_home)?;
    ensure_lock_binding(&store, &lock_binding)?;
    if read_state_at(&store)?.is_some() {
        return Err(HygieneStoreError::StateAlreadyExists);
    }

    let Some(legacy_bytes) = read_child_optional(&store, LEGACY_HYGIENE_STATE_FILE)? else {
        return Ok(HygieneMigrationOutcome::NoLegacyArtifact);
    };
    let legacy = parse_legacy_strict(&legacy_bytes)?;
    validate_legacy_bounds(&legacy)?;
    let plan = plan_legacy(legacy.clone()).map_err(HygieneStoreError::InvalidPlan)?;
    let state = HygieneState {
        schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
        revision: 1,
        raw_reflections: plan.retained_raw.clone(),
        period_reflections: legacy.period_reflections,
        topic_synonyms: legacy.topic_synonyms,
    };
    let bytes = serde_json::to_vec(&state).map_err(HygieneStoreError::InvalidSnapshot)?;
    if bytes.len() > MAX_HYGIENE_SNAPSHOT_BYTES {
        return Err(HygieneStoreError::CapacityExceeded);
    }
    ensure_lock_binding(&store, &lock_binding)?;
    let durability = match crate::skills::store::atomic_write_private_child_create_new_reported(
        &store.dir,
        OsStr::new(HYGIENE_STATE_FILE),
        &store.display_path.join(HYGIENE_STATE_FILE),
        &bytes,
    ) {
        Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
            HygieneDurability::Confirmed
        }
        Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
            HygieneDurability::RecoveryReadRequired
        }
        Err(error) if error_chain_has_kind(&error, std::io::ErrorKind::AlreadyExists) => {
            return Err(HygieneStoreError::StateAlreadyExists);
        }
        Err(_) => return Err(HygieneStoreError::SafeStoreUnavailable),
    };
    Ok(HygieneMigrationOutcome::Migrated(Box::new(
        HygieneApplyOutcome {
            state,
            plan,
            written: true,
            durability,
        },
    )))
}

fn lock_state(
    neoth_home: &Path,
) -> Result<
    (
        std::sync::MutexGuard<'static, ()>,
        crate::skills::store::BoundDirectory,
        std::fs::File,
        crate::skills::store::BoundChildObject,
    ),
    HygieneStoreError,
> {
    let process_lock = HYGIENE_STATE_LOCK
        .lock()
        .map_err(|_| HygieneStoreError::LockPoisoned)?;
    let store = open_hygiene_directory(neoth_home)?;
    let (os_lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &store.dir,
        OsStr::new("state-v1.lock"),
        &store.display_path.join("state-v1.lock"),
    )
    .map_err(|_| HygieneStoreError::LockUnavailable)?;
    acquire_bound_lock(&os_lock)?;
    Ok((process_lock, store, os_lock, lock_binding))
}

fn acquire_bound_lock(lock: &std::fs::File) -> Result<(), HygieneStoreError> {
    let started = std::time::Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= std::time::Duration::from_secs(5) {
                    return Err(HygieneStoreError::LockUnavailable);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return Err(HygieneStoreError::LockUnavailable),
        }
    }
}

fn open_hygiene_directory(
    neoth_home: &Path,
) -> Result<crate::skills::store::BoundDirectory, HygieneStoreError> {
    let home = crate::skills::store::open_absolute_bound_directory(
        neoth_home,
        false,
        "reflection hygiene home",
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?
    .ok_or(HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&home.dir)?;
    let reflections_path = neoth_home.join("reflections");
    let reflections = crate::skills::store::open_or_create_private_child_dir(
        &home.dir,
        OsStr::new("reflections"),
        &reflections_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&reflections)?;
    let display_path = reflections_path.join("hygiene");
    let dir = crate::skills::store::open_or_create_private_child_dir(
        &reflections,
        OsStr::new("hygiene"),
        &display_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&dir)?;
    Ok(crate::skills::store::BoundDirectory { dir, display_path })
}

fn open_daily_admission_directory(
    neoth_home: &Path,
) -> Result<crate::skills::store::BoundDirectory, HygieneStoreError> {
    let home = crate::skills::store::open_absolute_bound_directory(
        neoth_home,
        false,
        "daily admission home",
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?
    .ok_or(HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&home.dir)?;
    let reflections_path = neoth_home.join("reflections");
    let reflections = crate::skills::store::open_or_create_private_child_dir(
        &home.dir,
        OsStr::new("reflections"),
        &reflections_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&reflections)?;
    let display_path = reflections_path.join("daily-admission");
    let dir = crate::skills::store::open_or_create_private_child_dir(
        &reflections,
        OsStr::new("daily-admission"),
        &display_path,
    )
    .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    verify_private_hygiene_directory(&dir)?;
    Ok(crate::skills::store::BoundDirectory { dir, display_path })
}

fn verify_private_hygiene_directory(directory: &cap_std::fs::Dir) -> Result<(), HygieneStoreError> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        use cap_std::fs::PermissionsExt as _;

        let metadata = directory
            .dir_metadata()
            .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
        // SAFETY: `geteuid` has no memory or lifetime preconditions.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(HygieneStoreError::SafeStoreUnavailable);
        }
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::verify_private_directory_handle_dacl(directory)
            .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = directory;
    Ok(())
}

/// Tighten only a real current-user-owned legacy directory, then independently
/// verify the result through its existing directory handle. The capability
/// never follows a path after it has been opened.
fn tighten_legacy_private_directory(
    display_path: &Path,
    directory: &cap_std::fs::Dir,
) -> Result<(), HygieneStoreError> {
    #[cfg(not(windows))]
    let _ = display_path;
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = directory
            .dir_metadata()
            .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(HygieneStoreError::SafeStoreUnavailable);
        }
        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o077 != 0 {
            permissions.set_mode(0o700);
            directory
                .set_permissions(".", permissions)
                .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
        }
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(
            display_path,
            directory,
        )
        .map_err(|_| HygieneStoreError::SafeStoreUnavailable)?;
    }
    verify_private_hygiene_directory(directory)
}

fn ensure_lock_binding(
    store: &crate::skills::store::BoundDirectory,
    lock_binding: &crate::skills::store::BoundChildObject,
) -> Result<(), HygieneStoreError> {
    if lock_binding
        .matches_regular_file_child_readonly(
            &store.dir,
            OsStr::new("state-v1.lock"),
            &store.display_path.join("state-v1.lock"),
        )
        .map_err(|_| HygieneStoreError::LockUnavailable)?
    {
        Ok(())
    } else {
        Err(HygieneStoreError::LockUnavailable)
    }
}

fn validate_existing_state(state: &HygieneState, now_unix: i64) -> Result<(), HygieneStoreError> {
    plan_versioned(VersionedHygieneInput {
        schema_version: state.schema_version,
        now_unix,
        raw_reflections: state.raw_reflections.clone(),
        period_reflections: state.period_reflections.clone(),
        topic_synonyms: state.topic_synonyms.clone(),
    })
    .map(|_| ())
    .map_err(HygieneStoreError::InvalidPlan)
}

fn validate_input_bounds(input: &VersionedHygieneInput) -> Result<(), HygieneStoreError> {
    validate_collections(
        &input.raw_reflections,
        &input.period_reflections,
        &input.topic_synonyms,
    )
}

fn validate_legacy_bounds(input: &LegacyHygieneInput) -> Result<(), HygieneStoreError> {
    validate_collections(
        &input.raw_reflections,
        &input.period_reflections,
        &input.topic_synonyms,
    )
}

fn validate_state_bounds(state: &HygieneState) -> Result<(), HygieneStoreError> {
    validate_collections(
        &state.raw_reflections,
        &state.period_reflections,
        &state.topic_synonyms,
    )
}

fn validate_collections(
    raw_reflections: &[RawReflection],
    period_reflections: &[PeriodReflection],
    topic_synonyms: &TopicSynonymMap,
) -> Result<(), HygieneStoreError> {
    if raw_reflections.len() > MAX_HYGIENE_RAW_REFLECTIONS
        || period_reflections.len() > MAX_HYGIENE_PERIOD_REFLECTIONS
        || topic_synonyms.entries.len() > MAX_HYGIENE_SYNONYMS
    {
        return Err(HygieneStoreError::CapacityExceeded);
    }
    for raw in raw_reflections {
        validate_string_bound(&raw.id, MAX_HYGIENE_ID_BYTES)?;
        validate_period_bounds(&raw.reflection)?;
    }
    for reflection in period_reflections {
        validate_period_bounds(reflection)?;
    }
    for (alias, canonical) in &topic_synonyms.entries {
        validate_string_bound(alias, MAX_HYGIENE_TOPIC_BYTES)?;
        validate_string_bound(canonical, MAX_HYGIENE_TOPIC_BYTES)?;
    }
    validate_cumulative_input_bytes(raw_reflections, period_reflections, topic_synonyms)?;
    Ok(())
}

fn validate_cumulative_input_bytes(
    raw_reflections: &[RawReflection],
    period_reflections: &[PeriodReflection],
    topic_synonyms: &TopicSynonymMap,
) -> Result<(), HygieneStoreError> {
    let mut total = 0usize;
    for raw in raw_reflections {
        add_input_bytes(&mut total, raw.id.len())?;
        add_period_input_bytes(&mut total, &raw.reflection)?;
    }
    for reflection in period_reflections {
        add_period_input_bytes(&mut total, reflection)?;
    }
    for (alias, canonical) in &topic_synonyms.entries {
        add_input_bytes(&mut total, alias.len())?;
        add_input_bytes(&mut total, canonical.len())?;
    }
    Ok(())
}

fn add_period_input_bytes(
    total: &mut usize,
    reflection: &PeriodReflection,
) -> Result<(), HygieneStoreError> {
    add_input_bytes(total, reflection.kind.len())?;
    add_input_bytes(total, reflection.tag.len())?;
    add_input_bytes(total, reflection.body.len())?;
    for topic in &reflection.topics {
        add_input_bytes(total, topic.len())?;
    }
    for tag in &reflection.tags {
        add_input_bytes(total, tag.len())?;
    }
    Ok(())
}

fn add_input_bytes(total: &mut usize, bytes: usize) -> Result<(), HygieneStoreError> {
    *total = total
        .checked_add(bytes)
        .filter(|total| *total <= MAX_HYGIENE_IN_MEMORY_INPUT_BYTES)
        .ok_or(HygieneStoreError::CapacityExceeded)?;
    Ok(())
}

fn validate_period_bounds(reflection: &PeriodReflection) -> Result<(), HygieneStoreError> {
    validate_string_bound(&reflection.kind, MAX_HYGIENE_TAG_BYTES)?;
    validate_string_bound(&reflection.tag, MAX_HYGIENE_TAG_BYTES)?;
    validate_string_bound(&reflection.body, MAX_HYGIENE_BODY_BYTES)?;
    if reflection.topics.len() > MAX_HYGIENE_TOPICS_PER_REFLECTION
        || reflection.tags.len() > MAX_HYGIENE_TOPICS_PER_REFLECTION
    {
        return Err(HygieneStoreError::CapacityExceeded);
    }
    for topic in &reflection.topics {
        validate_string_bound(topic, MAX_HYGIENE_TOPIC_BYTES)?;
    }
    for tag in &reflection.tags {
        validate_string_bound(tag, MAX_HYGIENE_TAG_BYTES)?;
    }
    Ok(())
}

fn validate_string_bound(value: &str, max_bytes: usize) -> Result<(), HygieneStoreError> {
    if value.len() > max_bytes {
        return Err(HygieneStoreError::CapacityExceeded);
    }
    Ok(())
}

fn read_state_at(
    store: &crate::skills::store::BoundDirectory,
) -> Result<Option<HygieneState>, HygieneStoreError> {
    let Some(bytes) = read_child_optional(store, HYGIENE_STATE_FILE)? else {
        return Ok(None);
    };
    let state: HygieneState =
        serde_json::from_slice(&bytes).map_err(HygieneStoreError::InvalidSnapshot)?;
    if state.schema_version != HYGIENE_PLAN_SCHEMA_VERSION {
        return Err(HygieneStoreError::UnsupportedSnapshotVersion {
            found: state.schema_version,
        });
    }
    if state.revision == 0 {
        return Err(HygieneStoreError::InvalidSnapshotRevision { found: 0 });
    }
    validate_state_bounds(&state)?;
    Ok(Some(state))
}

fn read_child_optional(
    store: &crate::skills::store::BoundDirectory,
    name: &str,
) -> Result<Option<Vec<u8>>, HygieneStoreError> {
    match store.dir.symlink_metadata(OsStr::new(name)) {
        Ok(_) => crate::skills::store::read_regular_file_bounded(
            &store.dir,
            OsStr::new(name),
            &store.display_path.join(name),
            MAX_HYGIENE_SNAPSHOT_BYTES,
        )
        .map(Some)
        .map_err(|error| {
            if error_chain_has_kind(error.as_ref(), std::io::ErrorKind::InvalidData) {
                HygieneStoreError::CapacityExceeded
            } else {
                HygieneStoreError::SafeStoreUnavailable
            }
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(HygieneStoreError::SafeStoreUnavailable),
    }
}

fn deserialize_raw_reflections_strict<'de, D>(
    deserializer: D,
) -> Result<Vec<RawReflection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = <Vec<serde_json::Value> as serde::Deserialize>::deserialize(deserializer)?;
    if values.len() > MAX_HYGIENE_RAW_REFLECTIONS {
        return Err(serde::de::Error::custom("too many raw reflections"));
    }
    for value in &values {
        validate_raw_json_strict(value).map_err(serde::de::Error::custom)?;
    }
    values
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(serde::de::Error::custom))
        .collect()
}

fn deserialize_period_reflections_strict<'de, D>(
    deserializer: D,
) -> Result<Vec<PeriodReflection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = <Vec<serde_json::Value> as serde::Deserialize>::deserialize(deserializer)?;
    if values.len() > MAX_HYGIENE_PERIOD_REFLECTIONS {
        return Err(serde::de::Error::custom("too many period reflections"));
    }
    for value in &values {
        validate_period_json_strict(value).map_err(serde::de::Error::custom)?;
    }
    values
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(serde::de::Error::custom))
        .collect()
}

fn parse_legacy_strict(bytes: &[u8]) -> Result<LegacyHygieneInput, HygieneStoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(HygieneStoreError::InvalidSnapshot)?;
    let object = value.as_object().ok_or_else(|| {
        HygieneStoreError::InvalidSnapshot(json_shape_error(
            "legacy hygiene state must be an object",
        ))
    })?;
    reject_unknown_fields(
        object,
        &[
            "now_unix",
            "raw_reflections",
            "period_reflections",
            "topic_synonyms",
        ],
        "legacy hygiene state",
    )
    .map_err(|message| HygieneStoreError::InvalidSnapshot(json_shape_error(message)))?;
    for raw in array_field(object, "raw_reflections", "legacy hygiene state")? {
        validate_raw_json_strict(raw)
            .map_err(|message| HygieneStoreError::InvalidSnapshot(json_shape_error(message)))?;
    }
    for period in array_field(object, "period_reflections", "legacy hygiene state")? {
        validate_period_json_strict(period)
            .map_err(|message| HygieneStoreError::InvalidSnapshot(json_shape_error(message)))?;
    }
    serde_json::from_value(value).map_err(HygieneStoreError::InvalidSnapshot)
}

fn validate_raw_json_strict(value: &serde_json::Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "raw reflection must be an object".to_string())?;
    reject_unknown_fields(
        object,
        &["id", "recorded_at_unix", "reflection"],
        "raw reflection",
    )?;
    let reflection = object
        .get("reflection")
        .ok_or_else(|| "raw reflection is missing reflection".to_string())?;
    validate_period_json_strict(reflection)
}

fn validate_period_json_strict(value: &serde_json::Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "period reflection must be an object".to_string())?;
    reject_unknown_fields(
        object,
        &["kind", "tag", "generated_ts_unix", "topics", "body", "tags"],
        "period reflection",
    )
}

fn array_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
    owner: &str,
) -> Result<&'a Vec<serde_json::Value>, HygieneStoreError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            HygieneStoreError::InvalidSnapshot(json_shape_error(format!(
                "{owner} field {name:?} must be an array"
            )))
        })
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    owner: &str,
) -> Result<(), String> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("{owner} has unknown field {field:?}"));
    }
    Ok(())
}

fn json_shape_error(message: impl Into<String>) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn error_chain_has_kind(
    error: &(dyn std::error::Error + 'static),
    expected: std::io::ErrorKind,
) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == expected)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn write_state_at(
    store: &crate::skills::store::BoundDirectory,
    state: &HygieneState,
) -> Result<HygieneDurability, HygieneStoreError> {
    let bytes = serde_json::to_vec(state).map_err(HygieneStoreError::InvalidSnapshot)?;
    if bytes.len() > MAX_HYGIENE_SNAPSHOT_BYTES {
        return Err(HygieneStoreError::CapacityExceeded);
    }
    match crate::skills::store::atomic_write_private_child_reported(
        &store.dir,
        OsStr::new(HYGIENE_STATE_FILE),
        &store.display_path.join(HYGIENE_STATE_FILE),
        &bytes,
    ) {
        Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
            Ok(HygieneDurability::Confirmed)
        }
        Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
            Ok(HygieneDurability::RecoveryReadRequired)
        }
        Err(_) => Err(HygieneStoreError::SafeStoreUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::error::Error as _;

    const DAY: i64 = 86_400;

    #[test]
    fn stale_daily_admission_cas_fixture_is_home_scoped_and_cross_thread() {
        let home = test_home();
        let unrelated_home = test_home();
        let _fault_scope = fail_next_daily_admission_cas_as_stale_for_test(home.path());
        let home_path = home.path().to_path_buf();

        let observed_by_test_worker = std::thread::spawn(move || {
            let guard = lock_daily_admission(&home_path)
                .expect("worker must acquire its private daily-admission gate");
            guard
                .compare_and_set(0, "2026-08-27", DailyAdmissionOutcome::Suppressed, None)
                .is_err()
        })
        .join()
        .expect("stale-CAS worker must complete");
        assert!(
            observed_by_test_worker,
            "the scoped synthetic race must reach the worker that settles this home"
        );
        let unrelated_guard = lock_daily_admission(unrelated_home.path())
            .expect("an unrelated private home must acquire its own gate");
        assert!(matches!(
            unrelated_guard.compare_and_set(
                0,
                "2026-08-27",
                DailyAdmissionOutcome::Suppressed,
                None,
            ),
            Ok(HygieneDurability::Confirmed | HygieneDurability::RecoveryReadRequired)
        ));
        drop(unrelated_guard);
        assert!(
            lock_daily_admission(home.path())
                .expect("the worker's scope must not leave its gate locked")
                .load()
                .expect("the worker's empty state must remain readable")
                .is_none()
        );
    }

    struct TestHome {
        _root: crate::test_env::CanonicalTempDir,
        path: PathBuf,
    }

    impl TestHome {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn test_home() -> TestHome {
        let root = crate::test_env::canonical_tempdir().expect("private test root");
        #[cfg(unix)]
        let path = {
            use std::os::unix::fs::DirBuilderExt as _;

            let path = root.path().join("private-home");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("create private Unix test home");
            path
        };
        #[cfg(windows)]
        let path = {
            let path = root.path().join("private-home");
            crate::wal::win_native::create_private_directory_new(&path)
                .expect("create private Windows test home");
            path
        };
        TestHome { _root: root, path }
    }

    fn prepare_private_hygiene_namespace(home: &TestHome) {
        open_hygiene_directory(home.path()).expect("create private hygiene namespace");
    }

    #[test]
    fn error_chain_kind_detects_nested_invalid_data() {
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bounded-read test failure",
        ))
        .context("outer hygiene read context");

        assert!(error_chain_has_kind(
            error.as_ref(),
            std::io::ErrorKind::InvalidData
        ));
        assert!(!error_chain_has_kind(
            error.as_ref(),
            std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn error_chain_kind_rejects_non_matching_nested_io_kind() {
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bounded-read test failure",
        ))
        .context("outer hygiene read context");

        assert!(!error_chain_has_kind(
            error.as_ref(),
            std::io::ErrorKind::InvalidData
        ));
        assert!(error_chain_has_kind(
            error.as_ref(),
            std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn error_chain_kind_detects_private_child_precommit_source() {
        let home = test_home();
        let store = open_hygiene_directory(home.path()).expect("create private hygiene store");
        let name = OsStr::new("already-exists.json");
        let path = store.display_path.join("already-exists.json");
        let commit = crate::skills::store::atomic_write_private_child_create_new_reported(
            &store.dir,
            name,
            &path,
            b"first value",
        )
        .expect("create initial private child");
        assert!(matches!(
            commit,
            crate::skills::store::PrivateChildCommit::PublishedAndSynced
                | crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)
        ));
        let error = crate::skills::store::atomic_write_private_child_create_new_reported(
            &store.dir,
            name,
            &path,
            b"second value",
        )
        .expect_err("existing private child must fail before commit");

        assert!(error_chain_has_kind(
            &error,
            std::io::ErrorKind::AlreadyExists
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ambient_group_readable_home_is_rejected_before_hygiene_creation() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().expect("ambient test home");
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make ambient home group-readable");
        assert!(matches!(
            open_hygiene_directory(home.path()),
            Err(HygieneStoreError::SafeStoreUnavailable)
        ));
        assert!(!home.path().join("reflections").exists());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_daily_namespace_is_owner_checked_and_tightened_before_the_gate() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = test_home();
        let reflections = home.path().join("reflections");
        let daily = reflections.join("daily");
        std::fs::create_dir(&reflections).unwrap();
        std::fs::create_dir(&daily).unwrap();
        std::fs::set_permissions(&reflections, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&daily, std::fs::Permissions::from_mode(0o755)).unwrap();

        prepare_daily_admission_namespace(home.path()).unwrap();
        assert_eq!(
            std::fs::metadata(&reflections)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&daily).unwrap().permissions().mode() & 0o777,
            0o700
        );
        lock_daily_admission(home.path()).expect("private daily gate opens after migration");
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_daily_namespace_is_bound_hardened_before_settlement() {
        let home = test_home();
        let reflections = home.path().join("reflections");
        let daily = reflections.join("daily");
        std::fs::create_dir(&reflections).unwrap();
        std::fs::create_dir(&daily).unwrap();
        prepare_daily_admission_namespace(home.path()).unwrap();
        let reflection = crate::reflection::periodic::build_reflection(
            crate::reflection::periodic::PeriodKind::Daily,
            "2026-08-27",
            &["windows-migration".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(
            crate::reflection::periodic::settle_daily_admission(
                home.path(),
                &reflection,
                None,
                None,
            )
            .is_ok()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_daily_guard_load_and_cas_revalidate_a_held_lock_readonly() {
        let home = test_home();
        let guard = lock_daily_admission(home.path()).expect("open private daily-admission guard");

        assert_eq!(guard.load().expect("read through held lock"), None);
        let durability = guard
            .compare_and_set(0, "2026-08-27", DailyAdmissionOutcome::Suppressed, None)
            .expect("CAS through held lock");
        assert!(matches!(
            durability,
            HygieneDurability::Confirmed | HygieneDurability::RecoveryReadRequired
        ));

        let state = guard
            .load()
            .expect("revalidate the same held lock after CAS")
            .expect("CAS state remains readable through the held lock");
        assert_eq!(state.revision, 1);
        assert_eq!(state.tag, "2026-08-27");
        assert_eq!(state.outcome, DailyAdmissionOutcome::Suppressed);
    }

    #[cfg(windows)]
    #[test]
    fn windows_daily_guard_destroys_lock_handles_before_process_gate_after_unlock_error() {
        let home = test_home();
        let mut guard =
            lock_daily_admission(home.path()).expect("open private daily-admission guard");
        guard
            .os_lock
            .as_ref()
            .expect("guard retains its OS lock")
            .unlock()
            .expect("pre-unlock the Windows range lock");

        let repeated_unlock = guard
            .release_os_lock_resources()
            .expect("the guard attempted its explicit unlock");
        assert!(
            repeated_unlock.is_err(),
            "Windows must report the deliberately repeated unlock"
        );
        assert!(guard.os_lock.is_none());
        assert!(guard.lock_binding.is_none());
        assert!(
            matches!(
                DAILY_ADMISSION_STATE_LOCK.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ),
            "the process gate must remain held after both OS handles are destroyed"
        );

        drop(guard);
        let successor_home = home.path().to_path_buf();
        let (send, receive) = std::sync::mpsc::channel();
        let successor = std::thread::spawn(move || {
            let opened = lock_daily_admission(&successor_home)
                .and_then(|successor_guard| successor_guard.load())
                .is_ok();
            send.send(opened).expect("report successor gate result");
        });
        assert!(
            receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("same-process successor must not remain behind a teardown handle"),
            "same-process successor must acquire the Daily gate"
        );
        successor.join().expect("successor worker joins");
    }

    fn period(kind: &str, tag: &str, at: i64, body: &str) -> PeriodReflection {
        PeriodReflection {
            kind: kind.to_string(),
            tag: tag.to_string(),
            generated_ts_unix: at,
            topics: vec!["Rust".to_string(), "ML".to_string()],
            body: body.to_string(),
            tags: vec!["historical".to_string()],
        }
    }

    fn raw(id: &str, at: i64, tag: &str, topics: &[&str]) -> RawReflection {
        RawReflection {
            id: id.to_string(),
            recorded_at_unix: at,
            reflection: PeriodReflection {
                kind: "daily".to_string(),
                tag: tag.to_string(),
                generated_ts_unix: at,
                topics: topics.iter().map(|topic| (*topic).to_string()).collect(),
                body: format!("body-{id}"),
                tags: vec![format!("tag-{id}")],
            },
        }
    }

    fn input(now_unix: i64) -> VersionedHygieneInput {
        VersionedHygieneInput {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            now_unix,
            raw_reflections: Vec::new(),
            period_reflections: Vec::new(),
            topic_synonyms: TopicSynonymMap::default(),
        }
    }

    #[test]
    fn strict_roundtrip_uses_only_the_v1_snapshot_shape() {
        let home = test_home();
        let now = 200 * DAY;
        let outcome = apply_hygiene_plan(home.path(), 0, input(now)).expect("apply");
        assert_eq!(outcome.state.revision, 1);
        assert_eq!(
            load_hygiene_state(home.path()).expect("load"),
            Some(outcome.state)
        );

        let path = hygiene_state_path(home.path());
        for malformed in [
            r#"{"schema_version":1,"revision":1,"raw_reflections":[],"period_reflections":[],"topic_synonyms":{"version":1,"entries":{}},"extra":true}"#,
            r#"{"schema_version":1,"revision":1,"raw_reflections":[],"period_reflections":[{"kind":"daily","tag":"2026-01-01","generated_ts_unix":1,"topics":[],"body":"x","extra":true}],"topic_synonyms":{"version":1,"entries":{}}}"#,
        ] {
            std::fs::write(&path, malformed).expect("inject unknown field");
            assert!(matches!(
                load_hygiene_state(home.path()),
                Err(HygieneStoreError::InvalidSnapshot(_))
            ));
        }
    }

    #[test]
    fn apply_retains_only_planned_raw_and_preserves_periods_and_synonyms() {
        let home = test_home();
        let now = 200 * DAY;
        let mut request = input(now);
        request.raw_reflections = vec![
            raw("expired", now - 91 * DAY, "2026-01-01", &["old"]),
            raw("keep", now - 2 * DAY, "2026-01-02", &["rust"]),
            raw("duplicate", now - DAY, "2026-01-03", &["RUST"]),
        ];
        request.period_reflections = vec![period("daily", "2026-01-04", now - DAY, "kept")];
        request
            .topic_synonyms
            .entries
            .insert("ML".to_string(), "Machine Learning".to_string());
        let expected_periods = request.period_reflections.clone();
        let expected_synonyms = request.topic_synonyms.clone();

        let outcome = apply_hygiene_plan(home.path(), 0, request).expect("apply");
        assert!(outcome.written);
        assert_eq!(outcome.plan.expired_raw.len(), 1);
        assert_eq!(outcome.plan.duplicate_raw.len(), 1);
        assert_eq!(outcome.state.raw_reflections.len(), 1);
        assert_eq!(outcome.state.raw_reflections[0].id, "keep");
        assert_eq!(outcome.state.period_reflections, expected_periods);
        assert_eq!(outcome.state.topic_synonyms, expected_synonyms);
    }

    #[test]
    fn equal_retained_snapshot_is_a_byte_stable_revision_no_op() {
        let home = test_home();
        let now = 200 * DAY;
        let mut request = input(now);
        request.raw_reflections = vec![raw("keep", now - DAY, "2026-01-01", &["rust"])];
        let first = apply_hygiene_plan(home.path(), 0, request.clone()).expect("first apply");
        let before = std::fs::read(hygiene_state_path(home.path())).expect("state bytes");
        let second = apply_hygiene_plan(home.path(), first.state.revision, request).expect("no-op");
        assert!(!second.written);
        assert_eq!(second.state.revision, first.state.revision);
        assert_eq!(
            std::fs::read(hygiene_state_path(home.path())).expect("state bytes"),
            before
        );
    }

    #[test]
    fn same_process_calls_wait_for_the_process_guard() {
        let home = test_home();
        let path = home.path().to_path_buf();
        let process_guard = HYGIENE_STATE_LOCK.lock().expect("unpoisoned process lock");
        let (done_send, done_receive) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            done_send
                .send(apply_hygiene_plan(&path, 0, input(200 * DAY)))
                .expect("report writer result");
        });
        assert!(
            done_receive
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "a same-process writer must wait for the process guard"
        );
        drop(process_guard);
        assert!(
            done_receive
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("writer result")
                .expect("writer success")
                .written
        );
        writer.join().expect("writer joins");
    }

    #[test]
    fn separate_store_calls_contend_on_os_lock_and_stale_writer_cannot_overwrite() {
        let home = test_home();
        let now = 200 * DAY;
        let first = apply_hygiene_plan(home.path(), 0, input(now)).expect("first apply");
        let before = std::fs::read(hygiene_state_path(home.path())).expect("state bytes");
        let lock_home = home.path().to_path_buf();
        let (held_send, held_receive) = std::sync::mpsc::channel();
        let (release_send, release_receive) = std::sync::mpsc::channel();
        let blocking_lock = std::thread::spawn(move || {
            let store = open_hygiene_directory(&lock_home).expect("secure namespace");
            let (lock, _binding) = crate::skills::store::open_or_create_bound_lockfile(
                &store.dir,
                OsStr::new("state-v1.lock"),
                &store.display_path.join("state-v1.lock"),
            )
            .expect("open bound lock");
            acquire_bound_lock(&lock).expect("hold OS lock");
            held_send.send(()).expect("announce lock");
            release_receive.recv().expect("release lock");
            drop(lock);
        });
        held_receive
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("OS lock is held");

        let mut changed = input(now);
        changed.raw_reflections = vec![raw("new", now - DAY, "2026-01-01", &["rust"])];
        let stale_home = home.path().to_path_buf();
        let (done_send, done_receive) = std::sync::mpsc::channel();
        let stale_writer = std::thread::spawn(move || {
            let outcome = apply_hygiene_plan(&stale_home, first.state.revision - 1, changed)
                .map(|_| ())
                .map_err(|error| error.to_string());
            done_send.send(outcome).expect("report stale outcome");
        });
        assert!(
            done_receive
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "apply must wait for the per-home OS lock"
        );
        release_send.send(()).expect("release holder");
        blocking_lock.join().expect("holder joins");

        let stale_error = done_receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("stale writer finishes")
            .expect_err("stale writer must not overwrite");
        stale_writer.join().expect("writer joins");
        assert!(stale_error.contains("stale hygiene snapshot revision"));
        assert!(matches!(
            load_hygiene_state(home.path()),
            Ok(Some(HygieneState { revision: 1, .. }))
        ));
        assert_eq!(
            std::fs::read(hygiene_state_path(home.path())).expect("state bytes"),
            before
        );
    }

    #[test]
    fn corrupt_or_unsupported_state_refuses_rewrite() {
        let home = test_home();
        let now = 200 * DAY;
        apply_hygiene_plan(home.path(), 0, input(now)).expect("first apply");
        let path = hygiene_state_path(home.path());
        for bytes in [
            b"not-json".as_slice(),
            br#"{"schema_version":2,"revision":1,"raw_reflections":[],"period_reflections":[],"topic_synonyms":{"version":1,"entries":{}}}"#
                .as_slice(),
        ] {
            std::fs::write(&path, bytes).expect("inject state");
            assert!(apply_hygiene_plan(home.path(), 1, input(now)).is_err());
            assert_eq!(std::fs::read(&path).expect("state bytes"), bytes);
        }
    }

    #[test]
    fn invalid_plan_leaves_existing_snapshot_byte_stable() {
        let home = test_home();
        let now = 200 * DAY;
        apply_hygiene_plan(home.path(), 0, input(now)).expect("first apply");
        let path = hygiene_state_path(home.path());
        let before = std::fs::read(&path).expect("state bytes");
        let mut invalid = input(now);
        invalid.raw_reflections = vec![raw("", now - DAY, "2026-01-01", &["rust"])];
        assert!(matches!(
            apply_hygiene_plan(home.path(), 1, invalid),
            Err(HygieneStoreError::InvalidPlan(_))
        ));
        assert_eq!(std::fs::read(path).expect("state bytes"), before);
    }

    #[test]
    fn legacy_requires_explicit_migration_and_apply_preserves_every_byte() {
        let home = test_home();
        let now = 200 * DAY;
        let legacy = LegacyHygieneInput {
            now_unix: now,
            raw_reflections: Vec::new(),
            period_reflections: Vec::new(),
            topic_synonyms: TopicSynonymMap::default(),
        };
        let legacy_path = legacy_hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        let bytes = serde_json::to_vec(&legacy).expect("legacy json");
        std::fs::write(&legacy_path, &bytes).expect("legacy write");

        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, input(now)),
            Err(HygieneStoreError::LegacyMigrationRequired)
        ));
        assert!(!hygiene_state_path(home.path()).exists());
        assert_eq!(std::fs::read(&legacy_path).expect("legacy bytes"), bytes);
    }

    #[test]
    fn persisted_zero_revision_is_rejected_without_rewrite() {
        let home = test_home();
        let now = 200 * DAY;
        let path = hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        let bytes = br#"{"schema_version":1,"revision":0,"raw_reflections":[],"period_reflections":[],"topic_synonyms":{"version":1,"entries":{}}}"#;
        std::fs::write(&path, bytes).expect("inject zero revision");

        assert!(matches!(
            load_hygiene_state(home.path()),
            Err(HygieneStoreError::InvalidSnapshotRevision { found: 0 })
        ));
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, input(now)),
            Err(HygieneStoreError::InvalidSnapshotRevision { found: 0 })
        ));
        assert_eq!(std::fs::read(&path).expect("state bytes"), bytes);
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_json_allocation_or_rewrite() {
        let home = test_home();
        let path = hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        let bytes = vec![b'x'; MAX_HYGIENE_SNAPSHOT_BYTES + 1];
        std::fs::write(&path, &bytes).expect("inject oversized state");

        assert!(matches!(
            load_hygiene_state(home.path()),
            Err(HygieneStoreError::CapacityExceeded)
        ));
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, input(200 * DAY)),
            Err(HygieneStoreError::CapacityExceeded)
        ));
        assert_eq!(std::fs::read(&path).expect("state bytes"), bytes);
    }

    #[test]
    fn persisted_structural_caps_are_rejected_before_planning_or_rewrite() {
        let home = test_home();
        let now = 200 * DAY;
        let path = hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        let state = HygieneState {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            revision: 1,
            raw_reflections: (0..=MAX_HYGIENE_RAW_REFLECTIONS)
                .map(|index| raw(&format!("raw-{index}"), now - DAY, "2026-01-01", &["rust"]))
                .collect(),
            period_reflections: Vec::new(),
            topic_synonyms: TopicSynonymMap::default(),
        };
        let bytes = serde_json::to_vec(&state).expect("bounded state json");
        assert!(bytes.len() <= MAX_HYGIENE_SNAPSHOT_BYTES);
        std::fs::write(&path, &bytes).expect("inject over-cap state");

        assert!(matches!(
            apply_hygiene_plan(home.path(), 1, input(now)),
            Err(HygieneStoreError::InvalidSnapshot(_))
        ));
        assert_eq!(std::fs::read(path).expect("state bytes"), bytes);
    }

    #[test]
    fn candidate_record_and_synonym_caps_refuse_before_persistence() {
        let home = test_home();
        let now = 200 * DAY;
        let mut oversized_body = input(now);
        oversized_body.period_reflections = vec![period(
            "daily",
            "2026-01-01",
            now - DAY,
            &"x".repeat(MAX_HYGIENE_BODY_BYTES + 1),
        )];
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, oversized_body),
            Err(HygieneStoreError::CapacityExceeded)
        ));

        let mut too_many_synonyms = input(now);
        for index in 0..=MAX_HYGIENE_SYNONYMS {
            too_many_synonyms
                .topic_synonyms
                .entries
                .insert(format!("alias-{index}"), format!("canonical-{index}"));
        }
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, too_many_synonyms),
            Err(HygieneStoreError::CapacityExceeded)
        ));
        assert!(!hygiene_state_path(home.path()).exists());
    }

    #[test]
    fn cumulative_candidate_bytes_fail_before_clone_or_rewrite() {
        let home = test_home();
        let now = 200 * DAY;
        apply_hygiene_plan(home.path(), 0, input(now)).expect("first apply");
        let path = hygiene_state_path(home.path());
        let before = std::fs::read(&path).expect("state bytes");
        let body = "x".repeat(MAX_HYGIENE_BODY_BYTES - 1);
        let mut oversized = input(now);
        oversized.period_reflections = (0..5)
            .map(|index| period("daily", &format!("2026-01-{index:02}"), now - DAY, &body))
            .collect();

        assert!(matches!(
            apply_hygiene_plan(home.path(), 1, oversized),
            Err(HygieneStoreError::CapacityExceeded)
        ));
        assert_eq!(std::fs::read(path).expect("state bytes"), before);
    }

    #[test]
    fn public_debug_and_error_chains_do_not_expose_reflection_content() {
        let secret_id = "reflection-id-secret";
        let secret_tag = "tag-secret";
        let secret_body = "body-secret";
        let secret_path = "C:/private/path-secret";
        let state = HygieneState {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            revision: 1,
            raw_reflections: vec![raw(secret_id, DAY, secret_tag, &[secret_tag])],
            period_reflections: vec![period("daily", secret_tag, DAY, secret_body)],
            topic_synonyms: TopicSynonymMap {
                version: 1,
                entries: BTreeMap::from([(secret_tag.to_string(), secret_body.to_string())]),
            },
        };
        let plan = plan_versioned(input(200 * DAY)).expect("empty plan");
        let outcome = HygieneApplyOutcome {
            state,
            plan,
            written: true,
            durability: HygieneDurability::Confirmed,
        };
        let errors = [
            HygieneStoreError::Io {
                action: "read",
                source: std::io::Error::other(secret_path),
            },
            HygieneStoreError::InvalidSnapshot(json_shape_error(secret_body)),
            HygieneStoreError::InvalidPlan(HygieneError::DuplicateRawId {
                id: secret_id.to_string(),
            }),
        ];

        for value in [format!("{outcome:?}"), format!("{:?}", &errors[0])]
            .into_iter()
            .chain(errors.iter().map(|error| error.to_string()))
            .chain(errors.iter().map(|error| format!("{error:?}")))
        {
            for secret in [secret_id, secret_tag, secret_body, secret_path] {
                assert!(!value.contains(secret), "public diagnostic leaked content");
            }
        }
        assert!(errors.iter().all(|error| error.source().is_none()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_unknown_parent_sync_and_uses_bound_lock_cas_handles() {
        let home = test_home();
        let store_one = open_hygiene_directory(home.path()).expect("first bound directory");
        let (lock_one, binding_one) = crate::skills::store::open_or_create_bound_lockfile(
            &store_one.dir,
            OsStr::new("state-v1.lock"),
            &store_one.display_path.join("state-v1.lock"),
        )
        .expect("first bound lock");
        let store_two = open_hygiene_directory(home.path()).expect("second bound directory");
        let (lock_two, binding_two) = crate::skills::store::open_or_create_bound_lockfile(
            &store_two.dir,
            OsStr::new("state-v1.lock"),
            &store_two.display_path.join("state-v1.lock"),
        )
        .expect("second bound lock");
        assert!(
            binding_one
                .matches_regular_file_child_readonly(
                    &store_one.dir,
                    OsStr::new("state-v1.lock"),
                    &store_one.display_path.join("state-v1.lock"),
                )
                .expect("first binding check")
        );
        assert!(
            binding_two
                .matches_regular_file_child_readonly(
                    &store_two.dir,
                    OsStr::new("state-v1.lock"),
                    &store_two.display_path.join("state-v1.lock"),
                )
                .expect("second binding check")
        );
        drop(lock_one);
        drop(lock_two);

        let first = apply_hygiene_plan(home.path(), 0, input(200 * DAY)).expect("first apply");
        assert_eq!(first.durability, HygieneDurability::RecoveryReadRequired);
        let before = std::fs::read(hygiene_state_path(home.path())).expect("state bytes");
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, input(200 * DAY)),
            Err(HygieneStoreError::StaleRevision { .. })
        ));
        assert_eq!(
            std::fs::read(hygiene_state_path(home.path())).expect("state bytes"),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_namespace_or_leaf_is_refused_without_touching_outside_sentinel() {
        use std::os::unix::fs::symlink;

        let home = test_home();
        let outside = tempfile::tempdir().expect("outside");
        let sentinel = outside.path().join("sentinel.json");
        std::fs::write(&sentinel, b"outside").expect("sentinel");
        symlink(outside.path(), home.path().join("reflections")).expect("namespace symlink");
        assert!(matches!(
            apply_hygiene_plan(home.path(), 0, input(200 * DAY)),
            Err(HygieneStoreError::SafeStoreUnavailable)
        ));
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel bytes"),
            b"outside"
        );

        std::fs::remove_file(home.path().join("reflections")).expect("remove namespace link");
        let state_path = hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        symlink(&sentinel, &state_path).expect("state symlink");
        assert!(matches!(
            load_hygiene_state(home.path()),
            Err(HygieneStoreError::SafeStoreUnavailable)
        ));
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel bytes"),
            b"outside"
        );
    }

    #[test]
    fn migration_is_one_time_and_preserves_every_legacy_field() {
        let home = test_home();
        let now = 200 * DAY;
        let mut aliases = BTreeMap::new();
        aliases.insert("ML".to_string(), "Machine Learning".to_string());
        let legacy = LegacyHygieneInput {
            now_unix: now,
            raw_reflections: vec![raw("keep", now - DAY, "2026-01-01", &["ML"])],
            period_reflections: vec![period("daily", "2026-01-02", now - DAY, "legacy body")],
            topic_synonyms: TopicSynonymMap {
                version: 1,
                entries: aliases,
            },
        };
        let legacy_path = legacy_hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy json");
        std::fs::write(&legacy_path, &legacy_bytes).expect("legacy write");

        let outcome = migrate_legacy_hygiene_state(home.path()).expect("migrate");
        let HygieneMigrationOutcome::Migrated(outcome) = outcome else {
            panic!("expected migration");
        };
        assert_eq!(outcome.state.period_reflections, legacy.period_reflections);
        assert_eq!(outcome.state.topic_synonyms, legacy.topic_synonyms);
        assert_eq!(
            std::fs::read(&legacy_path).expect("legacy remains"),
            legacy_bytes
        );
        assert!(matches!(
            migrate_legacy_hygiene_state(home.path()),
            Err(HygieneStoreError::StateAlreadyExists)
        ));
    }

    #[test]
    fn failed_migration_leaves_no_v1_artifact() {
        let home = test_home();
        let now = 200 * DAY;
        let invalid = LegacyHygieneInput {
            now_unix: now,
            raw_reflections: vec![raw("", now - DAY, "2026-01-01", &["rust"])],
            period_reflections: Vec::new(),
            topic_synonyms: TopicSynonymMap::default(),
        };
        let legacy_path = legacy_hygiene_state_path(home.path());
        prepare_private_hygiene_namespace(&home);
        std::fs::write(
            &legacy_path,
            serde_json::to_vec(&invalid).expect("legacy json"),
        )
        .expect("legacy write");
        assert!(matches!(
            migrate_legacy_hygiene_state(home.path()),
            Err(HygieneStoreError::InvalidPlan(_))
        ));
        assert!(!hygiene_state_path(home.path()).exists());
        assert!(legacy_path.exists());
    }

    #[test]
    fn period_inputs_survive_raw_retention_without_yearly_materialization() {
        let home = test_home();
        let now = 500 * DAY;
        let mut request = input(now);
        request.raw_reflections = vec![raw("expired", now - 91 * DAY, "2026-01-01", &["raw"])];
        request.period_reflections = vec![period("daily", "2026-01-02", now - DAY, "daily body")];
        let outcome = apply_hygiene_plan(home.path(), 0, request).expect("apply");
        assert!(outcome.state.raw_reflections.is_empty());
        assert_eq!(outcome.state.period_reflections.len(), 1);
        assert_eq!(outcome.plan.yearly_inputs.len(), 1);
        assert_eq!(
            outcome.plan.yearly_inputs[0].source_tags,
            vec!["2026-01-02"]
        );
    }

    #[test]
    fn state_target_is_private_v1_path_and_leaves_no_temp_file() {
        let home = test_home();
        let path = hygiene_state_path(home.path());
        assert_eq!(
            path,
            home.path()
                .join("reflections")
                .join("hygiene")
                .join("state-v1.json")
        );
        apply_hygiene_plan(home.path(), 0, input(200 * DAY)).expect("apply");
        let mut names = std::fs::read_dir(path.parent().expect("parent"))
            .expect("read state dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![HYGIENE_STATE_FILE.to_string(), "state-v1.lock".to_string()]
        );
    }
}
