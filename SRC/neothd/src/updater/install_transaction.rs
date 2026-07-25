//! Crash-safe multi-member installation transactions.
//!
//! Callers supply an explicit target allowlist and already-prepared file or
//! directory sources. This module copies every source to a sibling staging
//! path on the target filesystem, journals every state transition durably,
//! then swaps all members into place. Recovery either restores every original
//! member or finalizes an already-committed new bundle.
//!
//! On Unix, staged data and journal files are flushed before rename and parent
//! directories are fsynced where the filesystem supports it. On Windows,
//! bundle-member renames use `MoveFileExW(MOVEFILE_WRITE_THROUGH)`. Journal
//! publication remains handle-bound (so a temp-path substitution cannot win),
//! flushes the file before the atomic rename, and is process-crash safe. Win32
//! exposes no equivalent directory-fsync proof for that handle-bound rename,
//! so this module does not claim journal namespace durability across sudden
//! power loss on every Windows filesystem.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const JOURNAL_SCHEMA_VERSION: u32 = 1;
const JOURNAL_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MEMBERS: usize = 512;
const LOCK_PREFIX: &str = ".neoth-install-";
const JOURNAL_SUFFIX: &str = ".journal.json";

/// Files and directories deliberately use different digest and copy rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    File,
    Directory,
}

/// One exact path the caller permits this transaction to replace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedTarget {
    path: PathBuf,
    kind: MemberKind,
}

impl AllowedTarget {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: MemberKind::File,
        }
    }

    pub fn directory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: MemberKind::Directory,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> MemberKind {
        self.kind
    }
}

/// A caller-prepared source and its explicitly allowed final target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMember {
    source: Option<PathBuf>,
    target: PathBuf,
    kind: MemberKind,
}

impl PreparedMember {
    pub fn file(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: Some(source.into()),
            target: target.into(),
            kind: MemberKind::File,
        }
    }

    pub fn directory(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: Some(source.into()),
            target: target.into(),
            kind: MemberKind::Directory,
        }
    }

    /// Declare that `target` must be absent after commit. If an old target is
    /// present it is backed up and restored by rollback exactly like a
    /// replacement member.
    pub fn absent(target: impl Into<PathBuf>, kind: MemberKind) -> Self {
        Self {
            source: None,
            target: target.into(),
            kind,
        }
    }

    pub fn absent_file(target: impl Into<PathBuf>) -> Self {
        Self::absent(target, MemberKind::File)
    }

    pub fn absent_directory(target: impl Into<PathBuf>) -> Self {
        Self::absent(target, MemberKind::Directory)
    }

    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn kind(&self) -> MemberKind {
        self.kind
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub transaction_id: String,
    pub members: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Clean,
    RolledBack { transaction_id: String },
    FinalizedCommit { transaction_id: String },
}

/// Reusable transaction coordinator for one logical installation root.
///
/// The lock and journal are deterministic sidecars in one stable, existing
/// state anchor. This permits a clean-machine install without creating the
/// install root before acquiring the OS lock and keeps the lock identity stable
/// when a formerly missing install root appears.
#[derive(Clone, Debug)]
pub struct InstallTransaction {
    install_root: PathBuf,
    lock_parent: PathBuf,
    lock_path: PathBuf,
    journal_path: PathBuf,
    root_existed_at_new: bool,
    allowed: BTreeMap<PathBuf, MemberKind>,
}

impl InstallTransaction {
    pub fn new(
        install_root: impl AsRef<Path>,
        allowed_targets: impl IntoIterator<Item = AllowedTarget>,
    ) -> Result<Self> {
        let anchor = default_transaction_anchor()?;
        Self::new_with_anchor(install_root, allowed_targets, anchor)
    }

    /// Construct against an explicit already-existing state anchor. Installers
    /// normally use [`Self::new`]; this is useful to bind system-wide package
    /// managers to their own protected state directory and for hermetic tests.
    pub fn new_with_anchor(
        install_root: impl AsRef<Path>,
        allowed_targets: impl IntoIterator<Item = AllowedTarget>,
        state_anchor: impl AsRef<Path>,
    ) -> Result<Self> {
        let requested_root = absolute_lexical(install_root.as_ref())?;
        if requested_root.parent().is_none() {
            anyhow::bail!("installation root cannot be a filesystem root");
        }
        let (install_root, root_existed_at_new) = canonical_future_path(&requested_root)?;
        if root_existed_at_new {
            require_real_directory(&install_root, "installation root")?;
        }

        let anchor = absolute_lexical(state_anchor.as_ref())?;
        require_real_directory(&anchor, "installation transaction state anchor")?;
        let lock_parent = fs::canonicalize(&anchor).with_context(|| {
            format!("canonicalize transaction state anchor {}", anchor.display())
        })?;
        let root_hash = path_identity_hash(&install_root)?;
        let lock_path = lock_parent.join(format!("{LOCK_PREFIX}{root_hash}.lock"));
        let journal_path = lock_parent.join(format!("{LOCK_PREFIX}{root_hash}{JOURNAL_SUFFIX}"));

        let mut allowed = BTreeMap::new();
        for target in allowed_targets {
            let requested = absolute_lexical(&target.path)?;
            let (path, _) = canonical_future_path(&requested)?;
            if path.file_name().is_none() {
                anyhow::bail!(
                    "allowed target cannot be a filesystem root: {}",
                    path.display()
                );
            }
            if path == lock_path
                || path == journal_path
                || lock_path.starts_with(&path)
                || journal_path.starts_with(&path)
            {
                anyhow::bail!(
                    "allowed target overlaps transaction metadata: {}",
                    path.display()
                );
            }
            if let Some(previous) = allowed.insert(path.clone(), target.kind)
                && previous != target.kind
            {
                anyhow::bail!(
                    "allowed target {} is declared as both file and directory",
                    path.display()
                );
            }
        }
        if allowed.is_empty() {
            anyhow::bail!(
                "installation transaction requires an explicit non-empty target allowlist"
            );
        }

        Ok(Self {
            install_root,
            lock_parent,
            lock_path,
            journal_path,
            root_existed_at_new,
            allowed,
        })
    }

    pub fn install_root(&self) -> &Path {
        &self.install_root
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn recover(&self) -> Result<RecoveryOutcome> {
        let _lock = self.acquire_lock()?;
        self.revalidate_after_lock()?;
        self.recover_locked()
    }

    pub fn apply(&self, members: &[PreparedMember]) -> Result<CommitReceipt> {
        let _lock = self.acquire_lock()?;
        self.revalidate_after_lock()?;
        let _ = self.recover_locked()?;

        let (mut journal, prepared) = self.prepare_journal(members)?;
        self.write_journal(&journal)?;
        test_hook(HookPoint::StatePrepared)?;

        let apply_result = self.stage_and_apply(&mut journal, &prepared);
        if let Err(apply_error) = apply_result {
            return match self.rollback_controlled(&mut journal) {
                Ok(()) => Err(apply_error.context("installation transaction failed and was rolled back")),
                Err(rollback_error) => Err(apply_error.context(format!(
                    "installation transaction failed; rollback remains journaled for recovery: {rollback_error:#}"
                ))),
            };
        }

        let receipt = CommitReceipt {
            transaction_id: journal.transaction_id.clone(),
            members: journal.members.len(),
        };
        self.finish_committed(&journal).with_context(|| {
            format!(
                "transaction {} committed the complete new bundle but cleanup remains journaled",
                journal.transaction_id
            )
        })?;
        Ok(receipt)
    }

    fn acquire_lock(&self) -> Result<File> {
        reject_link_if_present(&self.lock_path, "installation lock")?;
        let lock = crate::util::locked_file::lock_file_blocking(
            &self.lock_path,
            "installation transaction",
        )?;
        let metadata = fs::symlink_metadata(&self.lock_path)
            .with_context(|| format!("inspect installation lock {}", self.lock_path.display()))?;
        if metadata_is_link_like(&metadata) || !metadata.is_file() {
            anyhow::bail!(
                "installation lock is not a regular non-link file: {}",
                self.lock_path.display()
            );
        }
        verify_open_path_identity(&lock, &self.lock_path, "installation lock")?;
        Ok(lock)
    }

    fn revalidate_after_lock(&self) -> Result<()> {
        require_real_directory(&self.lock_parent, "installation lock parent")?;
        match fs::symlink_metadata(&self.install_root) {
            Ok(metadata) => {
                if !self.root_existed_at_new {
                    anyhow::bail!(
                        "installation root {} appeared while acquiring the lock; retry with a fresh transaction coordinator",
                        self.install_root.display()
                    );
                }
                validate_real_directory_metadata(
                    &self.install_root,
                    &metadata,
                    "installation root",
                )?;
                let canonical = fs::canonicalize(&self.install_root).with_context(|| {
                    format!(
                        "canonicalize installation root {}",
                        self.install_root.display()
                    )
                })?;
                if canonical != self.install_root {
                    anyhow::bail!(
                        "installation root identity changed while acquiring the lock: expected {}, found {}",
                        self.install_root.display(),
                        canonical.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.root_existed_at_new {
                    anyhow::bail!(
                        "installation root {} disappeared while acquiring the lock",
                        self.install_root.display()
                    );
                }
                let parent = self
                    .install_root
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("installation root has no parent"))?;
                require_real_directory(
                    nearest_existing_path(parent)?,
                    "installation root ancestor",
                )?;
            }
            Err(error) => return Err(error).context("revalidate installation root after lock"),
        }
        reject_link_if_present(&self.journal_path, "installation journal")?;
        Ok(())
    }

    fn prepare_journal(
        &self,
        members: &[PreparedMember],
    ) -> Result<(Journal, Vec<PreparedSource>)> {
        if members.is_empty() || members.len() > MAX_MEMBERS {
            anyhow::bail!(
                "installation transaction member count must be 1..={MAX_MEMBERS}, got {}",
                members.len()
            );
        }
        if self.journal_path.exists() {
            anyhow::bail!(
                "installation journal {} still exists after recovery",
                self.journal_path.display()
            );
        }

        let transaction_id = uuid::Uuid::new_v4().simple().to_string();
        let mut journal_members = Vec::with_capacity(members.len());
        let mut prepared = Vec::with_capacity(members.len());
        let mut targets = BTreeSet::new();

        for (index, member) in members.iter().enumerate() {
            let source = member
                .source
                .as_deref()
                .map(|source| {
                    let requested = absolute_lexical(source)?;
                    let (canonical, exists) = canonical_future_path(&requested)?;
                    if !exists {
                        anyhow::bail!("prepared source does not exist: {}", canonical.display());
                    }
                    Ok(canonical)
                })
                .transpose()?;
            let target_requested = absolute_lexical(&member.target)?;
            let (target, _) = canonical_future_path(&target_requested)?;
            match self.allowed.get(&target) {
                Some(kind) if *kind == member.kind => {}
                Some(kind) => anyhow::bail!(
                    "target {} is allowlisted as {kind:?}, not {:?}",
                    target.display(),
                    member.kind
                ),
                None => anyhow::bail!(
                    "target is not in the caller allowlist: {}",
                    target.display()
                ),
            }
            if !targets.insert(target.clone()) {
                anyhow::bail!("duplicate transaction target: {}", target.display());
            }
            if target == self.install_root && member.kind != MemberKind::Directory {
                anyhow::bail!("the installation root itself can only be a directory member");
            }

            let stage = work_path(&target, &transaction_id, index, "stage")?;
            let backup = work_path(&target, &transaction_id, index, "backup")?;
            reject_existing_work_path(&stage)?;
            reject_existing_work_path(&backup)?;

            let desired = source
                .as_deref()
                .map(|source| {
                    digest_artifact(source, member.kind)
                        .with_context(|| format!("digest prepared source {}", source.display()))
                })
                .transpose()?;
            let original = digest_optional(&target, member.kind)
                .with_context(|| format!("digest installation target {}", target.display()))?;

            journal_members.push(JournalMember {
                kind: member.kind,
                target: target.clone(),
                stage: stage.clone(),
                backup: backup.clone(),
                desired,
                original,
            });
            prepared.push(PreparedSource {
                source,
                target,
                stage,
                backup,
                kind: member.kind,
            });
        }

        reject_overlapping_targets(&targets)?;
        reject_source_work_overlap(&prepared)?;
        let created_directories = planned_parent_directories(
            &self.install_root,
            prepared.iter().map(|member| member.target.as_path()),
        )?;

        Ok((
            Journal {
                transaction_id,
                install_root: self.install_root.clone(),
                lock_path: self.lock_path.clone(),
                journal_path: self.journal_path.clone(),
                state: JournalState::Prepared,
                created_directories,
                members: journal_members,
            },
            prepared,
        ))
    }

    fn stage_and_apply(&self, journal: &mut Journal, prepared: &[PreparedSource]) -> Result<()> {
        create_planned_directories(&journal.created_directories)?;
        test_hook(HookPoint::DirectoriesReady)?;

        for (index, member) in prepared.iter().enumerate() {
            if let Some(source) = &member.source {
                copy_artifact(source, &member.stage, member.kind).with_context(|| {
                    format!(
                        "stage {:?} {} for {}",
                        member.kind,
                        source.display(),
                        member.target.display()
                    )
                })?;
                let staged = digest_artifact(&member.stage, member.kind)?;
                if Some(&staged) != journal.members[index].desired.as_ref() {
                    anyhow::bail!(
                        "staged digest mismatch for {}: expected {}, got {}",
                        member.target.display(),
                        journal.members[index]
                            .desired
                            .as_ref()
                            .map(|digest| digest.sha256.as_str())
                            .unwrap_or("absent"),
                        staged.sha256
                    );
                }
            }
            test_hook(HookPoint::StageReady(index))?;
        }

        for (index, member) in prepared.iter().enumerate() {
            let expected_original = journal.members[index].original.clone();
            if digest_optional(&member.target, member.kind)? != expected_original {
                anyhow::bail!(
                    "target {} changed after preflight; refusing replacement",
                    member.target.display()
                );
            }

            self.persist_state(
                journal,
                JournalState::Applying {
                    index,
                    phase: ApplyPhase::BackupPending,
                },
                HookPoint::StateApplying(index, ApplyPhase::BackupPending),
            )?;
            if expected_original.is_some() {
                if uses_copy_backup(member.kind, journal.members[index].desired.as_ref()) {
                    copy_artifact(&member.target, &member.backup, member.kind)?;
                    if digest_optional(&member.backup, member.kind)? != expected_original {
                        anyhow::bail!(
                            "copied backup digest mismatch for {}",
                            member.target.display()
                        );
                    }
                    test_hook(HookPoint::CopyTargetToBackup(index))?;
                } else {
                    durable_rename(&member.target, &member.backup)?;
                    test_hook(HookPoint::RenameTargetToBackup(index))?;
                }
            }

            self.persist_state(
                journal,
                JournalState::Applying {
                    index,
                    phase: ApplyPhase::BackupMoved,
                },
                HookPoint::StateApplying(index, ApplyPhase::BackupMoved),
            )?;
            if let Some(desired) = &journal.members[index].desired {
                if expected_original.is_some() && member.kind == MemberKind::File {
                    durable_replace_file(&member.stage, &member.target)?;
                    test_hook(HookPoint::ReplaceStageOverTarget(index))?;
                } else {
                    durable_rename(&member.stage, &member.target)?;
                    test_hook(HookPoint::RenameStageToTarget(index))?;
                }
                if digest_artifact(&member.target, member.kind)? != *desired {
                    anyhow::bail!("installed digest mismatch for {}", member.target.display());
                }
            } else if member.target.exists() {
                anyhow::bail!(
                    "absent member target still exists: {}",
                    member.target.display()
                );
            }

            self.persist_state(
                journal,
                JournalState::Applying {
                    index,
                    phase: ApplyPhase::Installed,
                },
                HookPoint::StateApplying(index, ApplyPhase::Installed),
            )?;
        }

        verify_complete_new(journal)?;
        self.persist_state(journal, JournalState::Committed, HookPoint::StateCommitted)?;
        Ok(())
    }

    fn persist_state(
        &self,
        journal: &mut Journal,
        state: JournalState,
        hook: HookPoint,
    ) -> Result<()> {
        journal.state = state;
        self.write_journal(journal)?;
        test_hook(hook)
    }

    fn rollback_controlled(&self, journal: &mut Journal) -> Result<()> {
        if journal.state == JournalState::Committed {
            anyhow::bail!("refusing to roll back a committed installation transaction");
        }
        if journal.state != JournalState::RollingBack {
            self.persist_state(
                journal,
                JournalState::RollingBack,
                HookPoint::StateRollingBack,
            )?;
        }
        rollback_members(journal)?;
        verify_complete_old(journal)?;
        cleanup_work_paths(journal, false)?;
        remove_created_directories(&journal.created_directories)?;
        self.remove_journal()
    }

    fn finish_committed(&self, journal: &Journal) -> Result<()> {
        verify_complete_new(journal)?;
        cleanup_work_paths(journal, true)?;
        self.remove_journal()
    }

    fn recover_locked(&self) -> Result<RecoveryOutcome> {
        self.sweep_orphan_journal_temps()?;
        if !self.journal_path.exists() {
            return Ok(RecoveryOutcome::Clean);
        }
        let mut journal = self.read_journal()?;
        self.validate_journal(&journal)?;
        let transaction_id = journal.transaction_id.clone();
        if journal.state == JournalState::Committed {
            self.finish_committed(&journal)?;
            return Ok(RecoveryOutcome::FinalizedCommit { transaction_id });
        }

        self.rollback_controlled(&mut journal)?;
        Ok(RecoveryOutcome::RolledBack { transaction_id })
    }

    /// Remove only temp files that match this coordinator's exact journal
    /// namespace. The caller holds the OS lock, and every candidate is opened
    /// without following links and identity-checked before deletion. A
    /// link-like, hard-linked, or otherwise manipulated candidate aborts
    /// recovery instead of being followed or removed.
    fn sweep_orphan_journal_temps(&self) -> Result<()> {
        require_real_directory(&self.lock_parent, "journal temp sweep anchor")?;
        let journal_name = self
            .journal_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("journal filename is not valid Unicode"))?;
        let prefix = format!(".{journal_name}.");

        for entry in fs::read_dir(&self.lock_parent)
            .with_context(|| format!("scan journal temp anchor {}", self.lock_parent.display()))?
        {
            let entry = entry.context("read journal temp anchor entry")?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(nonce) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".tmp"))
            else {
                continue;
            };
            if nonce.len() != 32
                || !nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                continue;
            }

            let candidate = entry.path();
            if candidate.parent() != Some(self.lock_parent.as_path()) {
                anyhow::bail!(
                    "journal temp escaped its transaction anchor: {}",
                    candidate.display()
                );
            }
            let (file, metadata) = open_regular_nofollow(&candidate)
                .with_context(|| format!("validate orphan journal temp {}", candidate.display()))?;
            if metadata.len() > JOURNAL_MAX_BYTES {
                anyhow::bail!(
                    "orphan journal temp exceeds the {JOURNAL_MAX_BYTES}-byte ceiling: {}",
                    candidate.display()
                );
            }
            verify_open_path_identity(&file, &candidate, "orphan journal temp")?;
            drop(file);
            fs::remove_file(&candidate)
                .with_context(|| format!("remove orphan journal temp {}", candidate.display()))?;
            sync_parent(&candidate)?;
        }
        Ok(())
    }

    fn write_journal(&self, journal: &Journal) -> Result<()> {
        let payload =
            serde_json::to_vec(journal).context("serialize installation journal payload")?;
        let envelope = JournalEnvelope {
            schema_version: JOURNAL_SCHEMA_VERSION,
            payload_sha256: hex::encode(Sha256::digest(&payload)),
            transaction: journal.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&envelope)
            .context("serialize installation journal envelope")?;
        if bytes.len() as u64 > JOURNAL_MAX_BYTES {
            anyhow::bail!("installation journal exceeds the {JOURNAL_MAX_BYTES}-byte ceiling");
        }
        durable_atomic_write_private(&self.journal_path, &bytes)
            .with_context(|| format!("write installation journal {}", self.journal_path.display()))
    }

    fn read_journal(&self) -> Result<Journal> {
        let (mut file, metadata) = open_regular_nofollow(&self.journal_path)
            .context("open installation journal without following links")?;
        if metadata.len() > JOURNAL_MAX_BYTES {
            anyhow::bail!("installation journal exceeds the {JOURNAL_MAX_BYTES}-byte ceiling");
        }
        verify_open_path_identity(&file, &self.journal_path, "installation journal")?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(JOURNAL_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| {
                format!("read installation journal {}", self.journal_path.display())
            })?;
        if bytes.len() as u64 > JOURNAL_MAX_BYTES {
            anyhow::bail!("installation journal exceeds the {JOURNAL_MAX_BYTES}-byte ceiling");
        }
        verify_open_path_identity(&file, &self.journal_path, "installation journal")?;
        let envelope: JournalEnvelope =
            serde_json::from_slice(&bytes).context("parse installation journal")?;
        if envelope.schema_version != JOURNAL_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported installation journal schema {}",
                envelope.schema_version
            );
        }
        let payload = serde_json::to_vec(&envelope.transaction)
            .context("serialize installation journal for integrity check")?;
        let actual = hex::encode(Sha256::digest(&payload));
        if !constant_time_eq(actual.as_bytes(), envelope.payload_sha256.as_bytes()) {
            anyhow::bail!("installation journal integrity digest mismatch");
        }
        Ok(envelope.transaction)
    }

    fn validate_journal(&self, journal: &Journal) -> Result<()> {
        validate_transaction_id(&journal.transaction_id)?;
        if journal.install_root != self.install_root
            || journal.lock_path != self.lock_path
            || journal.journal_path != self.journal_path
        {
            anyhow::bail!("installation journal metadata paths do not match this coordinator");
        }
        if journal.members.is_empty() || journal.members.len() > MAX_MEMBERS {
            anyhow::bail!("installation journal has an invalid member count");
        }
        let mut targets = BTreeSet::new();
        for (index, member) in journal.members.iter().enumerate() {
            match self.allowed.get(&member.target) {
                Some(kind) if *kind == member.kind => {}
                Some(_) => anyhow::bail!(
                    "journal target kind is not caller-allowed: {}",
                    member.target.display()
                ),
                None => anyhow::bail!(
                    "journal target is not in the caller allowlist: {}",
                    member.target.display()
                ),
            }
            if !targets.insert(member.target.clone()) {
                anyhow::bail!(
                    "journal contains duplicate target {}",
                    member.target.display()
                );
            }
            let expected_stage =
                work_path(&member.target, &journal.transaction_id, index, "stage")?;
            let expected_backup =
                work_path(&member.target, &journal.transaction_id, index, "backup")?;
            if member.stage != expected_stage || member.backup != expected_backup {
                anyhow::bail!(
                    "journal work paths were manipulated for target {}",
                    member.target.display()
                );
            }
            if let Some(desired) = &member.desired {
                validate_digest(desired)?;
            }
            if let Some(original) = &member.original {
                validate_digest(original)?;
            }
            let parent = member
                .target
                .parent()
                .ok_or_else(|| anyhow::anyhow!("journal target has no parent"))?;
            require_real_directory(nearest_existing_path(parent)?, "journal target ancestor")?;
        }
        reject_overlapping_targets(&targets)?;
        validate_created_directories(
            &journal.created_directories,
            &self.install_root,
            journal.members.iter().map(|member| member.target.as_path()),
        )?;
        match journal.state {
            JournalState::Applying { index, .. } if index >= journal.members.len() => {
                anyhow::bail!("installation journal applying index is out of bounds")
            }
            _ => {}
        }
        Ok(())
    }

    fn remove_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => sync_parent(&self.journal_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "remove installation journal {}",
                    self.journal_path.display()
                )
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct PreparedSource {
    source: Option<PathBuf>,
    target: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    kind: MemberKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema_version: u32,
    payload_sha256: String,
    transaction: Journal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    transaction_id: String,
    install_root: PathBuf,
    lock_path: PathBuf,
    journal_path: PathBuf,
    state: JournalState,
    created_directories: Vec<PathBuf>,
    members: Vec<JournalMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum JournalState {
    Prepared,
    Applying { index: usize, phase: ApplyPhase },
    Committed,
    RollingBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ApplyPhase {
    BackupPending,
    BackupMoved,
    Installed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalMember {
    kind: MemberKind,
    target: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    desired: Option<ArtifactDigest>,
    original: Option<ArtifactDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDigest {
    sha256: String,
    bytes: u64,
    files: u64,
    mode: Option<u32>,
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("read current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    let mut normal_depth = 0_usize;
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normal_depth == 0 {
                    anyhow::bail!("path escapes its filesystem root: {}", path.display());
                }
                normalized.pop();
                normal_depth -= 1;
            }
            Component::Normal(part) => {
                normalized.push(part);
                normal_depth += 1;
            }
        }
    }
    if !normalized.is_absolute() {
        anyhow::bail!(
            "path is not absolute after normalization: {}",
            path.display()
        );
    }
    normalized.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "transaction paths must be valid Unicode: {}",
            path.display()
        )
    })?;
    Ok(normalized)
}

fn canonical_future_path(path: &Path) -> Result<(PathBuf, bool)> {
    let absolute = absolute_lexical(path)?;
    let existed = match fs::symlink_metadata(&absolute) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("inspect path {}", absolute.display()));
        }
    };
    let cursor = if existed {
        absolute.as_path()
    } else {
        nearest_existing_path(
            absolute
                .parent()
                .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", absolute.display()))?,
        )?
    };
    ensure_no_link_components(cursor)?;
    let metadata = fs::symlink_metadata(cursor)?;
    if metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "path ancestor is a symlink/reparse point: {}",
            cursor.display()
        );
    }
    let canonical = fs::canonicalize(cursor)
        .with_context(|| format!("canonicalize path ancestor {}", cursor.display()))?;
    let suffix = absolute
        .strip_prefix(cursor)
        .context("derive future path suffix")?;
    // `PathBuf::join("")` preserves an observable trailing separator on
    // Windows.  For an already-existing regular file that turns `file.exe`
    // into `file.exe\\`, so the later no-follow open is interpreted as a
    // directory access and fails with ERROR_DIRECTORY.  Keep the canonical
    // object itself when there is no future suffix to append.
    let resolved = if suffix.as_os_str().is_empty() {
        canonical
    } else {
        canonical.join(suffix)
    };
    Ok((resolved, existed))
}

fn default_transaction_anchor() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("NEOTH_INSTALL_STATE_DIR")
        && !explicit.is_empty()
    {
        return Ok(PathBuf::from(explicit));
    }
    #[cfg(windows)]
    let anchor = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "LOCALAPPDATA/USERPROFILE is unavailable; set NEOTH_INSTALL_STATE_DIR to an existing protected directory"
            )
        })?;
    #[cfg(not(windows))]
    let anchor = std::env::var_os("HOME").ok_or_else(|| {
        anyhow::anyhow!(
            "HOME is unavailable; set NEOTH_INSTALL_STATE_DIR to an existing protected directory"
        )
    })?;
    Ok(PathBuf::from(anchor))
}

pub(super) fn nearest_existing_path(mut path: &Path) -> Result<&Path> {
    loop {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect path {}", path.display()));
            }
        }
        path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("path has no existing ancestor"))?;
    }
}

fn path_identity_hash(path: &Path) -> Result<String> {
    let identity = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("installation root must be valid Unicode"))?
        .replace('\\', "/");
    #[cfg(windows)]
    let identity = identity.to_lowercase();
    Ok(hex::encode(Sha256::digest(identity.as_bytes())))
}

fn work_path(target: &Path, transaction_id: &str, index: usize, suffix: &str) -> Result<PathBuf> {
    validate_transaction_id(transaction_id)?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("target has no parent: {}", target.display()))?;
    Ok(parent.join(format!(".neoth-install-{transaction_id}-{index}.{suffix}")))
}

fn validate_transaction_id(id: &str) -> Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid installation transaction id");
    }
    Ok(())
}

fn reject_overlapping_targets(targets: &BTreeSet<PathBuf>) -> Result<()> {
    let targets = targets.iter().collect::<Vec<_>>();
    for (index, left) in targets.iter().enumerate() {
        for right in targets.iter().skip(index + 1) {
            if left.starts_with(right.as_path()) || right.starts_with(left.as_path()) {
                anyhow::bail!(
                    "transaction targets overlap: {} and {}",
                    left.display(),
                    right.display()
                );
            }
        }
    }
    Ok(())
}

fn reject_source_work_overlap(members: &[PreparedSource]) -> Result<()> {
    for source in members {
        let Some(source_path) = &source.source else {
            continue;
        };
        for work in members {
            for path in [&work.target, &work.stage, &work.backup] {
                if source_path.starts_with(path) || path.starts_with(source_path) {
                    anyhow::bail!(
                        "prepared source {} overlaps transaction path {}",
                        source_path.display(),
                        path.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn planned_parent_directories<'a>(
    install_root: &Path,
    targets: impl Iterator<Item = &'a Path>,
) -> Result<Vec<PathBuf>> {
    let targets = targets.collect::<Vec<_>>();
    let mut needed = BTreeSet::new();
    if !targets
        .iter()
        .any(|target| install_root.starts_with(target))
    {
        collect_missing_directories(install_root, &mut needed)?;
    }
    for target in targets {
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("target has no parent: {}", target.display()))?;
        collect_missing_directories(parent, &mut needed)?;
    }
    let mut directories = needed.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| path.components().count());
    Ok(directories)
}

fn collect_missing_directories(path: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                validate_real_directory_metadata(cursor, &metadata, "directory ancestor")?;
                ensure_no_link_components(cursor)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    anyhow::anyhow!("directory has no existing ancestor: {}", path.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", cursor.display()));
            }
        }
    }
    for directory in missing.into_iter().rev() {
        out.insert(directory);
    }
    Ok(())
}

fn create_planned_directories(directories: &[PathBuf]) -> Result<()> {
    for directory in directories {
        match fs::create_dir(directory) {
            Ok(()) => sync_parent(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", directory.display()));
            }
        }
        require_real_directory(directory, "transaction-created directory")?;
    }
    Ok(())
}

fn remove_created_directories(directories: &[PathBuf]) -> Result<()> {
    for directory in directories.iter().rev() {
        match fs::remove_dir(directory) {
            Ok(()) => sync_parent(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", directory.display()));
            }
        }
    }
    Ok(())
}

fn validate_created_directories<'a>(
    directories: &[PathBuf],
    install_root: &Path,
    targets: impl Iterator<Item = &'a Path>,
) -> Result<()> {
    let mut permitted = BTreeSet::new();
    for ancestor in install_root.ancestors() {
        if !ancestor.as_os_str().is_empty() {
            permitted.insert(ancestor.to_path_buf());
        }
    }
    for leaf in targets.filter_map(Path::parent) {
        for ancestor in leaf.ancestors() {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            permitted.insert(ancestor.to_path_buf());
        }
    }
    let mut previous_depth = 0;
    let mut unique = BTreeSet::new();
    for directory in directories {
        if !permitted.contains(directory) || !unique.insert(directory) {
            anyhow::bail!(
                "journal contains a manipulated scaffold directory: {}",
                directory.display()
            );
        }
        let depth = directory.components().count();
        if depth < previous_depth {
            anyhow::bail!("journal scaffold directories are not parent-first");
        }
        previous_depth = depth;
    }
    Ok(())
}

fn verify_complete_new(journal: &Journal) -> Result<()> {
    for member in &journal.members {
        let actual = digest_optional(&member.target, member.kind)
            .with_context(|| format!("verify installed target {}", member.target.display()))?;
        if actual.as_ref() != member.desired.as_ref() {
            anyhow::bail!("new bundle digest mismatch at {}", member.target.display());
        }
    }
    Ok(())
}

fn verify_complete_old(journal: &Journal) -> Result<()> {
    for member in &journal.members {
        let actual = digest_optional(&member.target, member.kind)?;
        if actual.as_ref() != member.original.as_ref() {
            anyhow::bail!("old bundle was not restored at {}", member.target.display());
        }
    }
    Ok(())
}

fn rollback_members(journal: &Journal) -> Result<()> {
    for (index, member) in journal.members.iter().enumerate().rev() {
        let target = digest_optional(&member.target, member.kind)?;
        let backup = digest_optional(&member.backup, member.kind)?;
        match &member.original {
            Some(original) => {
                let copy_backed = uses_copy_backup(member.kind, member.desired.as_ref());
                if let Some(backup_digest) = &backup
                    && backup_digest != original
                {
                    if copy_backed && target.as_ref() == Some(original) {
                        // A process may die while copying the backup. The live
                        // target is still the verified original, so discard
                        // only this deterministic work path and roll back.
                        clear_work_path(&member.backup)?;
                    } else {
                        anyhow::bail!("backup digest mismatch at {}", member.backup.display());
                    }
                }
                if copy_backed {
                    match target {
                        Some(ref digest) if digest == original => {}
                        Some(ref digest) if member.desired.as_ref() == Some(digest) => {
                            let Some(_) = backup else {
                                anyhow::bail!(
                                    "cannot restore {} because its copied backup is missing",
                                    member.target.display()
                                );
                            };
                            durable_replace_file(&member.backup, &member.target)?;
                            test_hook(HookPoint::ReplaceBackupOverTarget(index))?;
                        }
                        None => anyhow::bail!(
                            "atomically replaced file target disappeared during recovery: {}",
                            member.target.display()
                        ),
                        Some(_) => anyhow::bail!(
                            "target {} matches neither journaled old nor new digest",
                            member.target.display()
                        ),
                    }
                    continue;
                }
                match target {
                    Some(ref digest)
                        if backup.is_some() && member.desired.as_ref() == Some(digest) =>
                    {
                        clear_work_path(&member.stage)?;
                        durable_rename(&member.target, &member.stage)?;
                        test_hook(HookPoint::RenameRollbackTargetToStage(index))?;
                        durable_rename(&member.backup, &member.target)?;
                        test_hook(HookPoint::RenameBackupToTarget(index))?;
                    }
                    Some(ref digest) if digest == original && backup.is_none() => {}
                    None => {
                        let Some(_) = backup else {
                            anyhow::bail!(
                                "cannot restore absent target {} because its backup is missing",
                                member.target.display()
                            );
                        };
                        durable_rename(&member.backup, &member.target)?;
                        test_hook(HookPoint::RenameBackupToTarget(index))?;
                    }
                    Some(_) => anyhow::bail!(
                        "target {} matches neither journaled old nor new digest",
                        member.target.display()
                    ),
                }
            }
            None => {
                if backup.is_some() {
                    anyhow::bail!(
                        "unexpected backup for originally absent target {}",
                        member.target.display()
                    );
                }
                match target {
                    None => {}
                    Some(ref digest) if member.desired.as_ref() == Some(digest) => {
                        clear_work_path(&member.stage)?;
                        durable_rename(&member.target, &member.stage)?;
                        test_hook(HookPoint::RenameRollbackTargetToStage(index))?;
                    }
                    Some(_) => anyhow::bail!(
                        "originally absent target {} contains unknown data",
                        member.target.display()
                    ),
                }
            }
        }
    }
    Ok(())
}

fn uses_copy_backup(kind: MemberKind, desired: Option<&ArtifactDigest>) -> bool {
    kind == MemberKind::File && desired.is_some()
}

fn cleanup_work_paths(journal: &Journal, committed: bool) -> Result<()> {
    for member in &journal.members {
        if committed
            && let Some(backup) = digest_optional(&member.backup, member.kind)?
            && Some(&backup) != member.original.as_ref()
        {
            anyhow::bail!(
                "refusing to delete mismatched backup {}",
                member.backup.display()
            );
        }
        clear_work_path(&member.stage)?;
        clear_work_path(&member.backup)?;
    }
    Ok(())
}

fn reject_existing_work_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("transaction work path already exists: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect work path {}", path.display())),
    }
}

fn clear_work_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata_is_link_like(&metadata) {
                anyhow::bail!("refusing to remove link-like work path {}", path.display());
            }
            remove_artifact(path, &metadata)?;
            sync_parent(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect work path {}", path.display())),
    }
}

fn remove_artifact(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata_is_link_like(metadata) {
        anyhow::bail!(
            "refusing to recursively remove link/reparse point {}",
            path.display()
        );
    }
    if metadata.is_file() {
        fs::remove_file(path).with_context(|| format!("remove file {}", path.display()))?;
    } else if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("read directory {}", path.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child = entry.path();
            let child_metadata = fs::symlink_metadata(&child)?;
            remove_artifact(&child, &child_metadata)?;
        }
        fs::remove_dir(path).with_context(|| format!("remove directory {}", path.display()))?;
    } else {
        anyhow::bail!("refusing to remove non-regular artifact {}", path.display());
    }
    Ok(())
}

fn copy_artifact(source: &Path, stage: &Path, kind: MemberKind) -> Result<()> {
    let parent = stage
        .parent()
        .ok_or_else(|| anyhow::anyhow!("stage has no parent: {}", stage.display()))?;
    require_real_directory(parent, "stage parent")?;
    match kind {
        MemberKind::File => {
            copy_regular_file(source, stage)?;
        }
        MemberKind::Directory => {
            copy_directory(source, stage)?;
        }
    }
    sync_parent(stage)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect source directory {}", source.display()))?;
    validate_real_directory_metadata(source, &source_metadata, "source directory")?;
    fs::create_dir(destination)
        .with_context(|| format!("create staged directory {}", destination.display()))?;

    let mut entries = fs::read_dir(source)
        .with_context(|| format!("read source directory {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("directory member name is not valid Unicode"))?;
        let source_child = entry.path();
        let destination_child = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_child)?;
        if metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "source directory contains a symlink/reparse point: {}",
                source_child.display()
            );
        }
        if metadata.is_dir() {
            copy_directory(&source_child, &destination_child)?;
        } else if metadata.is_file() {
            copy_regular_file(&source_child, &destination_child)?;
        } else {
            anyhow::bail!(
                "source contains a non-regular entry: {}",
                source_child.display()
            );
        }
    }
    fs::set_permissions(destination, source_metadata.permissions())?;
    sync_directory(destination)
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let (mut input, metadata) = open_regular_nofollow(source)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut output = options
        .open(destination)
        .with_context(|| format!("create staged file {}", destination.display()))?;
    let bytes = std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy {} to {}", source.display(), destination.display()))?;
    if bytes != metadata.len() {
        anyhow::bail!("source file changed while copying: {}", source.display());
    }
    output.set_permissions(metadata.permissions())?;
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn digest_optional(path: &Path, kind: MemberKind) -> Result<Option<ArtifactDigest>> {
    match fs::symlink_metadata(path) {
        Ok(_) => digest_artifact(path, kind).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect artifact {}", path.display())),
    }
}

fn digest_artifact(path: &Path, kind: MemberKind) -> Result<ArtifactDigest> {
    if let Some(parent) = path.parent() {
        ensure_no_link_components(parent)?;
    }
    match kind {
        MemberKind::File => digest_file(path),
        MemberKind::Directory => digest_directory(path),
    }
}

fn digest_file(path: &Path) -> Result<ArtifactDigest> {
    let (mut file, metadata) = open_regular_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {} for SHA-256", path.display()))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("file byte count overflow"))?;
        hasher.update(&buffer[..read]);
    }
    if bytes != metadata.len() {
        anyhow::bail!("file changed while hashing: {}", path.display());
    }
    Ok(ArtifactDigest {
        sha256: hex::encode(hasher.finalize()),
        bytes,
        files: 1,
        mode: Some(permission_fingerprint(&metadata)),
    })
}

fn digest_directory(root: &Path) -> Result<ArtifactDigest> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect directory {}", root.display()))?;
    validate_real_directory_metadata(root, &metadata, "directory artifact")?;
    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH-TREE-SHA256-V1\0");
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    digest_directory_into(root, root, &mut hasher, &mut files, &mut bytes)?;
    Ok(ArtifactDigest {
        sha256: hex::encode(hasher.finalize()),
        bytes,
        files,
        mode: None,
    })
}

fn digest_directory_into(
    root: &Path,
    directory: &Path,
    hasher: &mut Sha256,
    files: &mut u64,
    bytes: &mut u64,
) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    validate_real_directory_metadata(directory, &metadata, "directory member")?;
    hash_tree_record(
        hasher,
        b'D',
        relative_tree_path(root, directory)?.as_bytes(),
        permission_fingerprint(&metadata),
        0,
        None,
    );
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("directory member name is not valid Unicode"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata_is_link_like(&metadata) {
            anyhow::bail!("tree contains a symlink/reparse point: {}", path.display());
        }
        if metadata.is_dir() {
            digest_directory_into(root, &path, hasher, files, bytes)?;
        } else if metadata.is_file() {
            let digest = digest_file(&path)?;
            *files = files
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("tree file count overflow"))?;
            *bytes = bytes
                .checked_add(digest.bytes)
                .ok_or_else(|| anyhow::anyhow!("tree byte count overflow"))?;
            hash_tree_record(
                hasher,
                b'F',
                relative_tree_path(root, &path)?.as_bytes(),
                digest.mode.unwrap_or_default(),
                digest.bytes,
                Some(&digest.sha256),
            );
        } else {
            anyhow::bail!("tree contains a non-regular entry: {}", path.display());
        }
    }
    Ok(())
}

fn hash_tree_record(
    hasher: &mut Sha256,
    kind: u8,
    relative: &[u8],
    mode: u32,
    bytes: u64,
    content_sha256: Option<&str>,
) {
    hasher.update([kind]);
    hasher.update((relative.len() as u64).to_le_bytes());
    hasher.update(relative);
    hasher.update(mode.to_le_bytes());
    hasher.update(bytes.to_le_bytes());
    if let Some(digest) = content_sha256 {
        hasher.update(digest.as_bytes());
    }
}

fn relative_tree_path(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .context("tree walk escaped root")?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("tree path is not valid Unicode"))
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn open_regular_nofollow(path: &Path) -> Result<(File, Metadata)> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect regular file {}", path.display()))?;
    if metadata_is_link_like(&before) || !before.is_file() {
        anyhow::bail!("expected regular non-link file: {}", path.display());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open regular file {}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata_is_link_like(&metadata) || !metadata.is_file() {
        anyhow::bail!(
            "opened path is not a regular non-link file: {}",
            path.display()
        );
    }
    Ok((file, metadata))
}

fn permission_fingerprint(metadata: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
        u32::from(metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0)
    }
    #[cfg(not(any(unix, windows)))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

fn durable_atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    durable_atomic_write_private_with(path, bytes, || uuid::Uuid::new_v4().simple().to_string())
}

fn durable_atomic_write_private_with<F>(path: &Path, bytes: &[u8], mut next_nonce: F) -> Result<()>
where
    F: FnMut() -> String,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("journal has no parent: {}", path.display()))?;
    require_real_directory(parent, "journal parent")?;
    reject_link_if_present(path, "installation journal")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("journal filename is not valid Unicode"))?;

    for _ in 0..32 {
        let nonce = next_nonce();
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("journal temp nonce must be 32 lowercase hexadecimal characters");
        }
        let temp_path = parent.join(format!(".{file_name}.{nonce}.tmp"));
        let file = match create_private_temp(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create journal temp {}", temp_path.display()));
            }
        };
        let mut pending = PendingJournalTemp::new(temp_path, file);
        pending.file_mut().write_all(bytes)?;
        pending.file_mut().flush()?;
        pending.file().sync_all()?;
        test_hook(HookPoint::JournalTempDurable)?;

        #[cfg(windows)]
        {
            crate::wal::win_native::replace_private_file_handle(pending.file(), path)?;
            pending.disarm();
        }
        #[cfg(not(windows))]
        {
            pending.close();
            fs::rename(pending.path(), path).with_context(|| {
                format!(
                    "publish journal {} -> {}",
                    pending.path().display(),
                    path.display()
                )
            })?;
            pending.disarm();
        }
        sync_parent(path)?;
        return Ok(());
    }
    anyhow::bail!("could not allocate a unique journal temp path after 32 attempts")
}

fn create_private_temp(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        crate::wal::win_native::create_private_file_new(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path)
    }
}

struct PendingJournalTemp {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl PendingJournalTemp {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path: Some(path),
            file: Some(file),
        }
    }

    #[cfg(not(windows))]
    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("pending journal path is present")
    }

    fn file(&self) -> &File {
        self.file.as_ref().expect("pending journal file is present")
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("pending journal file is present")
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for PendingJournalTemp {
    fn drop(&mut self) {
        self.close();
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn verify_open_path_identity(file: &File, path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let handle = file.metadata()?;
        let namespace = fs::symlink_metadata(path)?;
        if metadata_is_link_like(&namespace)
            || handle.dev() != namespace.dev()
            || handle.ino() != namespace.ino()
            || handle.nlink() != 1
            || namespace.nlink() != 1
        {
            anyhow::bail!(
                "{label} path is link-like, hard-linked, or changed while open: {}",
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
        let namespace = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ_WRITE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .with_context(|| format!("open lock namespace entry {}", path.display()))?;
        let metadata = namespace.metadata()?;
        if metadata_is_link_like(&metadata) {
            anyhow::bail!("{label} path is a reparse point: {}", path.display());
        }
        let handle_identity = windows_file_identity(file)?;
        let namespace_identity = windows_file_identity(&namespace)?;
        if handle_identity != namespace_identity || handle_identity.1 != 1 {
            anyhow::bail!(
                "{label} path is hard-linked or changed while open: {}",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<((u32, u64), u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a valid handle and `information` is writable storage
    // for the exact Win32 output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) }
        == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("query installation lock file identity");
    }
    // SAFETY: the successful Win32 call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((
        (information.dwVolumeSerialNumber, index),
        information.nNumberOfLinks,
    ))
}

fn durable_rename(from: &Path, to: &Path) -> Result<()> {
    if from.parent() != to.parent() {
        anyhow::bail!(
            "transaction rename must remain on one target filesystem: {} -> {}",
            from.display(),
            to.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

        match fs::symlink_metadata(to) {
            Ok(_) => anyhow::bail!(
                "transaction rename destination must be absent: {}",
                to.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect rename destination {}", to.display()));
            }
        }
        let from_wide = from
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let to_wide = to
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that
        // remain live for the complete call. Omitting REPLACE_EXISTING makes a
        // raced destination fail closed.
        if unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "write-through rename {} -> {}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
    #[cfg(not(windows))]
    {
        // Mirror the Windows fail-closed-on-raced-destination guard (R3-12): this
        // primitive renames onto an absent path — callers move any prior target
        // to backup or clear the stage first — so a destination that exists here
        // is a concurrent create between the backup move and the commit rename
        // and must NOT be silently clobbered by POSIX rename's replace semantics.
        // `durable_replace` is the separate primitive for intentional replacement.
        // ponytail: symlink_metadata + rename leaves a narrow TOCTOU; the atomic
        // upgrade is renameat2(RENAME_NOREPLACE) on Linux / renamex_np(RENAME_EXCL)
        // on macOS.
        match fs::symlink_metadata(to) {
            Ok(_) => anyhow::bail!(
                "transaction rename destination must be absent: {}",
                to.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect rename destination {}", to.display()));
            }
        }
        fs::rename(from, to)
            .with_context(|| format!("rename {} -> {}", from.display(), to.display()))?;
    }
    sync_parent(to)
}

/// Atomically replace an existing regular file while keeping the old pathname
/// valid until the filesystem commits the new one. The old bytes already live
/// in the transaction's independently verified copied backup.
fn durable_replace_file(from: &Path, to: &Path) -> Result<()> {
    if from.parent() != to.parent() {
        anyhow::bail!(
            "transaction replacement must remain on one target filesystem: {} -> {}",
            from.display(),
            to.display()
        );
    }
    let from_metadata = fs::symlink_metadata(from)
        .with_context(|| format!("inspect replacement source {}", from.display()))?;
    let to_metadata = fs::symlink_metadata(to)
        .with_context(|| format!("inspect replacement target {}", to.display()))?;
    if metadata_is_link_like(&from_metadata)
        || metadata_is_link_like(&to_metadata)
        || !from_metadata.is_file()
        || !to_metadata.is_file()
    {
        anyhow::bail!(
            "atomic transaction replacement requires two regular non-link files: {} -> {}",
            from.display(),
            to.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let from_wide = from
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let to_wide = to
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        if unsafe {
            MoveFileExW(
                from_wide.as_ptr(),
                to_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "write-through atomic replacement {} -> {}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
    #[cfg(not(windows))]
    fs::rename(from, to).with_context(|| {
        format!(
            "atomically replace {} with {}",
            to.display(),
            from.display()
        )
    })?;
    sync_parent(to)
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        match File::open(path).and_then(|directory| directory.sync_all()) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error).with_context(|| format!("fsync directory {}", path.display())),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn ensure_no_link_components(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect path component {}", ancestor.display()))?;
        if metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "path contains a symlink/reparse point: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<()> {
    ensure_no_link_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    validate_real_directory_metadata(path, &metadata, label)
}

fn validate_real_directory_metadata(path: &Path, metadata: &Metadata, label: &str) -> Result<()> {
    if metadata_is_link_like(metadata) || !metadata.is_dir() {
        anyhow::bail!("{label} must be a real directory: {}", path.display());
    }
    Ok(())
}

fn reject_link_if_present(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_link_like(&metadata) => {
            anyhow::bail!(
                "{label} must not be a symlink/reparse point: {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
    }
}

fn metadata_is_link_like(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn validate_digest(digest: &ArtifactDigest) -> Result<()> {
    if digest.sha256.len() != 64
        || !digest
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || digest.files > 1_000_000_000
    {
        anyhow::bail!("installation journal contains an invalid artifact digest");
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum HookPoint {
    JournalTempDurable,
    StatePrepared,
    DirectoriesReady,
    StageReady(usize),
    StateApplying(usize, ApplyPhase),
    CopyTargetToBackup(usize),
    RenameTargetToBackup(usize),
    ReplaceStageOverTarget(usize),
    RenameStageToTarget(usize),
    StateCommitted,
    StateRollingBack,
    RenameRollbackTargetToStage(usize),
    ReplaceBackupOverTarget(usize),
    RenameBackupToTarget(usize),
}

#[cfg(not(test))]
fn test_hook(_point: HookPoint) -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn test_hook(point: HookPoint) -> Result<()> {
    TEST_HOOK.with(|hook| {
        let action = hook.get();
        if action.is_some_and(|action| action.point() == point) {
            hook.set(None);
            match action.expect("checked Some") {
                TestHookAction::Exit(_) => std::process::exit(86),
                TestHookAction::Error(_) => anyhow::bail!("injected controlled error at {point:?}"),
            }
        }
        Ok(())
    })
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestHookAction {
    Exit(HookPoint),
    Error(HookPoint),
}

#[cfg(test)]
impl TestHookAction {
    fn point(self) -> HookPoint {
        match self {
            Self::Exit(point) | Self::Error(point) => point,
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HOOK: std::cell::Cell<Option<TestHookAction>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use tempfile::TempDir;

    const CHILD_ROOT: &str = "NEOTH_INSTALL_TXN_TEST_ROOT";
    const CHILD_FIXTURE: &str = "NEOTH_INSTALL_TXN_TEST_FIXTURE";
    const CHILD_MODE: &str = "NEOTH_INSTALL_TXN_TEST_MODE";
    const CHILD_HOOK: &str = "NEOTH_INSTALL_TXN_TEST_HOOK";

    struct StandardFixture {
        temp: TempDir,
        file_target: PathBuf,
        directory_target: PathBuf,
    }

    impl StandardFixture {
        fn new() -> Self {
            let temp = crate::test_env::canonical_tempdir().unwrap();
            seed_standard(temp.path());
            let install_root = temp.path().join("install");
            Self {
                file_target: install_root.join("neoth.bin"),
                directory_target: install_root.join("self-knowledge"),
                temp,
            }
        }

        fn root(&self) -> &Path {
            self.temp.path()
        }

        fn transaction(&self) -> InstallTransaction {
            standard_transaction(self.root())
        }

        fn assert_old(&self) {
            assert_eq!(fs::read(&self.file_target).unwrap(), b"old-binary");
            assert_eq!(
                fs::read(self.directory_target.join("old.txt")).unwrap(),
                b"old-tree"
            );
            assert!(!self.directory_target.join("new.txt").exists());
        }

        fn assert_new(&self) {
            assert_eq!(fs::read(&self.file_target).unwrap(), b"new-binary");
            assert_eq!(
                fs::read(self.directory_target.join("new.txt")).unwrap(),
                b"new-tree"
            );
            assert_eq!(
                fs::read(self.directory_target.join("nested/deep.txt")).unwrap(),
                b"deep"
            );
            assert!(!self.directory_target.join("old.txt").exists());
        }

        fn assert_clean(&self) {
            let transaction = self.transaction();
            assert!(!transaction.journal_path().exists());
            assert_no_work_residue(self.root());
        }
    }

    fn seed_standard(root: &Path) {
        let source = root.join("source");
        fs::create_dir_all(source.join("self-knowledge/nested")).unwrap();
        fs::write(source.join("neoth.bin"), b"new-binary").unwrap();
        fs::write(source.join("self-knowledge/new.txt"), b"new-tree").unwrap();
        fs::write(source.join("self-knowledge/nested/deep.txt"), b"deep").unwrap();

        let install = root.join("install");
        fs::create_dir_all(install.join("self-knowledge")).unwrap();
        fs::write(install.join("neoth.bin"), b"old-binary").unwrap();
        fs::write(install.join("self-knowledge/old.txt"), b"old-tree").unwrap();
    }

    #[test]
    fn canonical_temp_fixture_has_no_link_ancestors_and_keeps_file_identity() {
        let temp = crate::test_env::canonical_tempdir().unwrap();
        ensure_no_link_components(temp.path()).unwrap();
        let file = temp.path().join("member.bin");
        fs::write(&file, b"member").unwrap();
        let (resolved, existed) = canonical_future_path(&file).unwrap();
        assert!(existed);
        assert_eq!(resolved, fs::canonicalize(&file).unwrap());
        assert_eq!(resolved.file_name(), file.file_name());
    }

    fn standard_transaction(root: &Path) -> InstallTransaction {
        let install = root.join("install");
        InstallTransaction::new_with_anchor(
            &install,
            [
                AllowedTarget::file(install.join("neoth.bin")),
                AllowedTarget::directory(install.join("self-knowledge")),
            ],
            root,
        )
        .unwrap()
    }

    fn standard_members(root: &Path) -> Vec<PreparedMember> {
        let source = root.join("source");
        let install = root.join("install");
        vec![
            PreparedMember::file(source.join("neoth.bin"), install.join("neoth.bin")),
            PreparedMember::directory(
                source.join("self-knowledge"),
                install.join("self-knowledge"),
            ),
        ]
    }

    fn fresh_transaction(root: &Path) -> InstallTransaction {
        let install = root.join("deep/new/install");
        InstallTransaction::new_with_anchor(
            &install,
            [AllowedTarget::file(install.join("neoth.bin"))],
            root,
        )
        .unwrap()
    }

    fn fresh_members(root: &Path) -> Vec<PreparedMember> {
        vec![PreparedMember::file(
            root.join("source.bin"),
            root.join("deep/new/install/neoth.bin"),
        )]
    }

    fn identical_transaction(root: &Path) -> InstallTransaction {
        let install = root.join("install");
        InstallTransaction::new_with_anchor(
            &install,
            [AllowedTarget::file(install.join("same.bin"))],
            root,
        )
        .unwrap()
    }

    fn identical_members(root: &Path) -> Vec<PreparedMember> {
        vec![PreparedMember::file(
            root.join("same-source.bin"),
            root.join("install/same.bin"),
        )]
    }

    fn seed_absent(root: &Path) {
        let install = root.join("install");
        fs::create_dir_all(install.join("stale-dir")).unwrap();
        fs::write(install.join("stale.bin"), b"stale").unwrap();
        fs::write(install.join("stale-dir/file"), b"stale-dir").unwrap();
    }

    fn absent_transaction(root: &Path) -> InstallTransaction {
        let install = root.join("install");
        InstallTransaction::new_with_anchor(
            &install,
            [
                AllowedTarget::file(install.join("stale.bin")),
                AllowedTarget::directory(install.join("stale-dir")),
            ],
            root,
        )
        .unwrap()
    }

    fn absent_members(root: &Path) -> Vec<PreparedMember> {
        let install = root.join("install");
        vec![
            PreparedMember::absent_file(install.join("stale.bin")),
            PreparedMember::absent_directory(install.join("stale-dir")),
        ]
    }

    fn assert_absent_old(root: &Path) {
        assert_eq!(fs::read(root.join("install/stale.bin")).unwrap(), b"stale");
        assert_eq!(
            fs::read(root.join("install/stale-dir/file")).unwrap(),
            b"stale-dir"
        );
    }

    fn assert_absent_new(root: &Path) {
        assert!(!root.join("install/stale.bin").exists());
        assert!(!root.join("install/stale-dir").exists());
    }

    fn spawn_child(root: &Path, fixture: &str, mode: &str, hook: HookPoint) {
        let hook = serde_json::to_string(&hook).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("crash_child_entry")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, root)
            .env(CHILD_FIXTURE, fixture)
            .env(CHILD_MODE, mode)
            .env(CHILD_HOOK, hook)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(86),
            "child must exit at the requested non-unwinding killpoint"
        );
    }

    #[test]
    fn crash_child_entry() {
        let Some(root) = std::env::var_os(CHILD_ROOT) else {
            return;
        };
        let root = PathBuf::from(root);
        let fixture = std::env::var(CHILD_FIXTURE).unwrap();
        let mode = std::env::var(CHILD_MODE).unwrap();
        let hook: HookPoint = serde_json::from_str(&std::env::var(CHILD_HOOK).unwrap()).unwrap();
        TEST_HOOK.with(|cell| cell.set(Some(TestHookAction::Exit(hook))));

        match (fixture.as_str(), mode.as_str()) {
            ("standard", "apply") => {
                let _ = standard_transaction(&root).apply(&standard_members(&root));
            }
            ("standard", "recover") => {
                let _ = standard_transaction(&root).recover();
            }
            ("fresh", "apply") => {
                let _ = fresh_transaction(&root).apply(&fresh_members(&root));
            }
            ("identical", "apply") => {
                let _ = identical_transaction(&root).apply(&identical_members(&root));
            }
            ("absent", "apply") => {
                let _ = absent_transaction(&root).apply(&absent_members(&root));
            }
            ("portable-absent-root", "apply") => {
                // GOLD-R3-12 crash harness: portable first-install into an absent
                // root. NEOTH_INSTALL_STATE_DIR is pinned by the parent so the
                // journal lands in the test temp dir, not in LOCALAPPDATA/HOME.
                let _ = crate::updater::release_bundle::apply_portable_release_bundle(
                    root.join("bundle"),
                    root.join("install"),
                    env!("CARGO_PKG_VERSION"),
                );
            }
            ("portable-absent-root", "apply-recover") => {
                // Retry after a hard crash: clear the hook so no killpoint fires,
                // then attempt the portable first-install again over the leftover
                // partial. Exit code encodes the outcome for the parent:
                //    0 = self-healed (GOLD-R3-12a): apply_release_bundle recovers
                //        this root's own journaled crashed partial before the
                //        markerless guard, then commits a complete install.
                //   70 = quarantined: the markerless-first-install guard refused a
                //        silent retry (pre-R3-12a behavior; still the outcome for a
                //        foreign/prior install that carries no NEOTH journal).
                // Either way the crash never yields a silently-trusted partial.
                TEST_HOOK.with(|cell| cell.set(None));
                match crate::updater::release_bundle::apply_portable_release_bundle(
                    root.join("bundle"),
                    root.join("install"),
                    env!("CARGO_PKG_VERSION"),
                ) {
                    Err(_) => std::process::exit(70),
                    Ok(_) => std::process::exit(0),
                }
            }
            other => panic!("unknown child fixture/mode: {other:?}"),
        }
        panic!("child did not reach killpoint {hook:?}");
    }

    #[test]
    fn durable_rename_refuses_a_raced_existing_destination() {
        // GOLD-R3-12: durable_rename targets an absent path; a destination that
        // already exists (a concurrent create between the backup move and the
        // commit rename) must fail closed on EVERY OS — never silently clobber.
        // This locks the Windows guard's behavior onto the Unix path, which
        // previously used bare POSIX rename (replace-existing). `durable_replace`
        // remains the primitive for intentional replacement.
        let dir = TempDir::new().unwrap();
        let from = dir.path().join("stage");
        let to = dir.path().join("target");
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"raced-in").unwrap();

        let err = durable_rename(&from, &to)
            .expect_err("a pre-existing destination must fail closed, not clobber");
        assert!(
            err.to_string().contains("destination must be absent"),
            "unexpected error: {err:#}"
        );
        // The raced-in destination is preserved and the source is left intact for
        // the caller's rollback — nothing was moved.
        assert_eq!(fs::read(&to).unwrap(), b"raced-in");
        assert_eq!(fs::read(&from).unwrap(), b"new");
    }

    #[test]
    fn successful_file_and_directory_bundle_commits() {
        let fixture = StandardFixture::new();
        let receipt = fixture
            .transaction()
            .apply(&standard_members(fixture.root()))
            .unwrap();
        assert_eq!(receipt.members, 2);
        fixture.assert_new();
        fixture.assert_clean();
    }

    #[test]
    fn subprocess_crash_before_journal_publication_sweeps_private_temp() {
        let fixture = StandardFixture::new();
        let transaction = fixture.transaction();
        spawn_child(
            fixture.root(),
            "standard",
            "apply",
            HookPoint::JournalTempDurable,
        );
        assert!(!transaction.journal_path().exists());
        assert!(matches!(
            transaction.recover().unwrap(),
            RecoveryOutcome::Clean
        ));
        fixture.assert_old();
        fixture.assert_clean();
    }

    #[test]
    fn subprocess_recovery_covers_every_forward_state_and_rename() {
        let cases = [
            (HookPoint::StatePrepared, false),
            (HookPoint::DirectoriesReady, false),
            (HookPoint::StageReady(0), false),
            (HookPoint::StageReady(1), false),
            (
                HookPoint::StateApplying(0, ApplyPhase::BackupPending),
                false,
            ),
            (HookPoint::CopyTargetToBackup(0), false),
            (HookPoint::StateApplying(0, ApplyPhase::BackupMoved), false),
            (HookPoint::ReplaceStageOverTarget(0), false),
            (HookPoint::StateApplying(0, ApplyPhase::Installed), false),
            (
                HookPoint::StateApplying(1, ApplyPhase::BackupPending),
                false,
            ),
            (HookPoint::RenameTargetToBackup(1), false),
            (HookPoint::StateApplying(1, ApplyPhase::BackupMoved), false),
            (HookPoint::RenameStageToTarget(1), false),
            (HookPoint::StateApplying(1, ApplyPhase::Installed), false),
            (HookPoint::StateCommitted, true),
        ];

        for (hook, committed) in cases {
            let fixture = StandardFixture::new();
            spawn_child(fixture.root(), "standard", "apply", hook);
            let fresh = fixture.transaction();
            let outcome = fresh.recover().unwrap();
            if committed {
                assert!(matches!(outcome, RecoveryOutcome::FinalizedCommit { .. }));
                fixture.assert_new();
            } else {
                assert!(matches!(outcome, RecoveryOutcome::RolledBack { .. }));
                fixture.assert_old();
            }
            fixture.assert_clean();
        }
    }

    #[test]
    fn public_file_path_exists_at_both_sides_of_atomic_replacement() {
        for (hook, expected) in [
            (HookPoint::CopyTargetToBackup(0), b"old-binary".as_slice()),
            (
                HookPoint::ReplaceStageOverTarget(0),
                b"new-binary".as_slice(),
            ),
        ] {
            let fixture = StandardFixture::new();
            spawn_child(fixture.root(), "standard", "apply", hook);
            let metadata = fs::symlink_metadata(&fixture.file_target)
                .expect("public file pathname must never disappear");
            assert!(metadata.is_file());
            assert_eq!(fs::read(&fixture.file_target).unwrap(), expected);
            assert!(matches!(
                fixture.transaction().recover().unwrap(),
                RecoveryOutcome::RolledBack { .. }
            ));
            fixture.assert_old();
            fixture.assert_clean();
        }
    }

    #[test]
    fn subprocess_recovery_is_restart_safe_during_every_rollback_rename() {
        let rollback_hooks = [
            HookPoint::StateRollingBack,
            HookPoint::RenameRollbackTargetToStage(1),
            HookPoint::RenameBackupToTarget(1),
            HookPoint::ReplaceBackupOverTarget(0),
        ];
        for rollback_hook in rollback_hooks {
            let fixture = StandardFixture::new();
            spawn_child(
                fixture.root(),
                "standard",
                "apply",
                HookPoint::StateApplying(1, ApplyPhase::Installed),
            );
            spawn_child(fixture.root(), "standard", "recover", rollback_hook);
            let outcome = fixture.transaction().recover().unwrap();
            assert!(matches!(outcome, RecoveryOutcome::RolledBack { .. }));
            fixture.assert_old();
            fixture.assert_clean();
        }
    }

    #[test]
    fn controlled_error_rolls_back_without_leaving_a_journal() {
        let fixture = StandardFixture::new();
        TEST_HOOK.with(|cell| {
            cell.set(Some(TestHookAction::Error(
                HookPoint::ReplaceStageOverTarget(0),
            )))
        });
        let error = fixture
            .transaction()
            .apply(&standard_members(fixture.root()))
            .unwrap_err();
        assert!(format!("{error:#}").contains("rolled back"));
        fixture.assert_old();
        fixture.assert_clean();
    }

    #[test]
    fn deep_missing_root_reinstantiation_uses_the_same_anchor_and_recovers() {
        let temp = crate::test_env::canonical_tempdir().unwrap();
        fs::write(temp.path().join("source.bin"), b"fresh").unwrap();
        let before = fresh_transaction(temp.path());
        assert!(!before.install_root().exists());
        let lock = before.lock_path().to_path_buf();
        let journal = before.journal_path().to_path_buf();

        spawn_child(temp.path(), "fresh", "apply", HookPoint::DirectoriesReady);
        assert!(temp.path().join("deep/new/install").exists());
        let after = fresh_transaction(temp.path());
        assert_eq!(after.lock_path(), lock);
        assert_eq!(after.journal_path(), journal);
        assert!(matches!(
            after.recover().unwrap(),
            RecoveryOutcome::RolledBack { .. }
        ));
        assert!(!temp.path().join("deep").exists());
        assert!(!journal.exists());
        assert_no_work_residue(temp.path());
    }

    #[test]
    fn identical_old_and_new_digest_recovers_after_install_rename() {
        let temp = crate::test_env::canonical_tempdir().unwrap();
        fs::create_dir(temp.path().join("install")).unwrap();
        fs::write(temp.path().join("same-source.bin"), b"same").unwrap();
        fs::write(temp.path().join("install/same.bin"), b"same").unwrap();
        spawn_child(
            temp.path(),
            "identical",
            "apply",
            HookPoint::ReplaceStageOverTarget(0),
        );
        assert!(matches!(
            identical_transaction(temp.path()).recover().unwrap(),
            RecoveryOutcome::RolledBack { .. }
        ));
        assert_eq!(
            fs::read(temp.path().join("install/same.bin")).unwrap(),
            b"same"
        );
        assert_no_work_residue(temp.path());
    }

    #[test]
    fn absent_members_commit_and_crash_recovery_restores_old() {
        let temp = crate::test_env::canonical_tempdir().unwrap();
        seed_absent(temp.path());
        absent_transaction(temp.path())
            .apply(&absent_members(temp.path()))
            .unwrap();
        assert_absent_new(temp.path());
        assert_no_work_residue(temp.path());
    }

    #[test]
    fn subprocess_absent_file_and_directory_recovery_covers_every_member_phase() {
        let cases = [
            (
                HookPoint::StateApplying(0, ApplyPhase::BackupPending),
                false,
            ),
            (HookPoint::RenameTargetToBackup(0), false),
            (HookPoint::StateApplying(0, ApplyPhase::BackupMoved), false),
            (HookPoint::StateApplying(0, ApplyPhase::Installed), false),
            (
                HookPoint::StateApplying(1, ApplyPhase::BackupPending),
                false,
            ),
            (HookPoint::RenameTargetToBackup(1), false),
            (HookPoint::StateApplying(1, ApplyPhase::BackupMoved), false),
            (HookPoint::StateApplying(1, ApplyPhase::Installed), false),
            (HookPoint::StateCommitted, true),
        ];

        for (hook, committed) in cases {
            let temp = crate::test_env::canonical_tempdir().unwrap();
            seed_absent(temp.path());
            spawn_child(temp.path(), "absent", "apply", hook);
            let outcome = absent_transaction(temp.path()).recover().unwrap();
            if committed {
                assert!(matches!(outcome, RecoveryOutcome::FinalizedCommit { .. }));
                assert_absent_new(temp.path());
            } else {
                assert!(matches!(outcome, RecoveryOutcome::RolledBack { .. }));
                assert_absent_old(temp.path());
            }
            assert_no_work_residue(temp.path());
        }
    }

    #[test]
    fn journal_target_and_work_path_tampering_are_rejected_against_allowlist() {
        for tamper_target in [true, false] {
            let fixture = StandardFixture::new();
            spawn_child(
                fixture.root(),
                "standard",
                "apply",
                HookPoint::StatePrepared,
            );
            let transaction = fixture.transaction();
            let mut journal = transaction.read_journal().unwrap();
            if tamper_target {
                journal.members[0].target = fixture.root().join("outside.bin");
            } else {
                journal.members[0].stage = fixture.root().join("outside.stage");
            }
            rewrite_journal(transaction.journal_path(), &journal);
            let error = transaction.recover().unwrap_err();
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("allowlist") || diagnostic.contains("manipulated"),
                "unexpected tamper diagnostic: {diagnostic}"
            );
            fixture.assert_old();
        }
    }

    #[test]
    fn journal_integrity_tampering_is_rejected() {
        let fixture = StandardFixture::new();
        spawn_child(
            fixture.root(),
            "standard",
            "apply",
            HookPoint::StatePrepared,
        );
        let transaction = fixture.transaction();
        let mut bytes = fs::read(transaction.journal_path()).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'a').unwrap();
        bytes[position] = b'b';
        fs::write(transaction.journal_path(), bytes).unwrap();
        assert!(transaction.recover().is_err());
        fixture.assert_old();
    }

    #[test]
    fn lock_is_exclusive_and_hardlinks_are_rejected() {
        let fixture = StandardFixture::new();
        let transaction = fixture.transaction();
        let held = crate::util::locked_file::lock_file_blocking(
            transaction.lock_path(),
            "transaction test",
        )
        .unwrap();
        assert!(
            crate::util::locked_file::try_lock_file_once(
                transaction.lock_path(),
                "transaction test"
            )
            .unwrap()
            .is_none()
        );
        drop(held);

        fs::remove_file(transaction.lock_path()).unwrap();
        let victim = fixture.root().join("lock-victim");
        fs::write(&victim, b"do-not-touch").unwrap();
        fs::hard_link(&victim, transaction.lock_path()).unwrap();
        assert!(transaction.recover().is_err());
        assert_eq!(fs::read(victim).unwrap(), b"do-not-touch");
    }

    #[cfg(unix)]
    #[test]
    fn source_and_lock_symlinks_are_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let fixture = StandardFixture::new();
        let linked = fixture.root().join("source/self-knowledge/linked");
        symlink(fixture.root().join("source/neoth.bin"), &linked).unwrap();
        assert!(
            fixture
                .transaction()
                .apply(&standard_members(fixture.root()))
                .is_err()
        );
        fixture.assert_old();

        fs::remove_file(linked).unwrap();
        let transaction = fixture.transaction();
        if transaction.lock_path().exists() {
            fs::remove_file(transaction.lock_path()).unwrap();
        }
        let victim = fixture.root().join("symlink-victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, transaction.lock_path()).unwrap();
        assert!(transaction.recover().is_err());
        assert_eq!(fs::read(victim).unwrap(), b"victim");
    }

    #[test]
    fn private_journal_temp_collisions_never_clobber_existing_objects() {
        let temp = crate::test_env::canonical_tempdir().unwrap();
        let target = temp.path().join("journal.json");
        let collision_nonce = "11".repeat(16);
        let safe_nonce = "22".repeat(16);
        let collision = temp
            .path()
            .join(format!(".journal.json.{collision_nonce}.tmp"));
        let victim = temp.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        fs::hard_link(&victim, &collision).unwrap();
        let mut nonces = [collision_nonce, safe_nonce].into_iter();
        durable_atomic_write_private_with(&target, b"journal", || nonces.next().unwrap()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"journal");
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::read(&collision).unwrap(), b"victim");
    }

    #[test]
    fn orphan_temp_sweep_rejects_hardlinks_without_touching_the_victim() {
        let fixture = StandardFixture::new();
        let transaction = fixture.transaction();
        let victim = fixture.root().join("orphan-hardlink-victim");
        fs::write(&victim, b"victim").unwrap();
        let journal_name = transaction
            .journal_path()
            .file_name()
            .unwrap()
            .to_string_lossy();
        let orphan = fixture
            .root()
            .join(format!(".{journal_name}.{}.tmp", "55".repeat(16)));
        fs::hard_link(&victim, &orphan).unwrap();

        let error = transaction.recover().unwrap_err();
        assert!(format!("{error:#}").contains("hard-linked"));
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::read(&orphan).unwrap(), b"victim");
    }

    #[cfg(unix)]
    #[test]
    fn private_journal_temp_symlink_collision_is_skipped() {
        use std::os::unix::fs::symlink;

        let temp = crate::test_env::canonical_tempdir().unwrap();
        let target = temp.path().join("journal.json");
        let collision_nonce = "33".repeat(16);
        let safe_nonce = "44".repeat(16);
        let collision = temp
            .path()
            .join(format!(".journal.json.{collision_nonce}.tmp"));
        let victim = temp.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, &collision).unwrap();
        let mut nonces = [collision_nonce, safe_nonce].into_iter();
        durable_atomic_write_private_with(&target, b"journal", || nonces.next().unwrap()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"journal");
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
    }

    #[cfg(unix)]
    #[test]
    fn orphan_temp_sweep_rejects_symlinks_without_touching_the_victim() {
        use std::os::unix::fs::symlink;

        let fixture = StandardFixture::new();
        let transaction = fixture.transaction();
        let victim = fixture.root().join("orphan-symlink-victim");
        fs::write(&victim, b"victim").unwrap();
        let journal_name = transaction
            .journal_path()
            .file_name()
            .unwrap()
            .to_string_lossy();
        let orphan = fixture
            .root()
            .join(format!(".{journal_name}.{}.tmp", "66".repeat(16)));
        symlink(&victim, &orphan).unwrap();

        assert!(transaction.recover().is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(orphan.exists());
    }

    fn rewrite_journal(path: &Path, journal: &Journal) {
        let payload = serde_json::to_vec(journal).unwrap();
        let envelope = JournalEnvelope {
            schema_version: JOURNAL_SCHEMA_VERSION,
            payload_sha256: hex::encode(Sha256::digest(&payload)),
            transaction: journal.clone(),
        };
        durable_atomic_write_private(path, &serde_json::to_vec(&envelope).unwrap()).unwrap();
    }

    fn assert_no_work_residue(root: &Path) {
        fn visit(path: &Path) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                assert!(
                    !name.ends_with(".stage")
                        && !name.ends_with(".backup")
                        && !name.ends_with(JOURNAL_SUFFIX)
                        && !name.ends_with(".tmp"),
                    "transaction residue remains at {}",
                    path.display()
                );
                if entry.file_type().unwrap().is_dir() {
                    visit(&path);
                }
            }
        }
        visit(root);
    }
}
