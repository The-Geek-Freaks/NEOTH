//! Create-only, content-addressed document-note publication for explicitly
//! approved user knowledge. This module deliberately has no self-wiki or
//! Paperless path: its only effect is one immutable note below the selected
//! operator vault.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use sha2::{Digest as _, Sha256};

use crate::skills::store::{
    BoundDirectory, BoundDirectoryChild, DirectorySyncOutcome, PrivateChildCommit,
    PrivateChildDurabilityUnknown, atomic_write_private_child_create_new_reported,
    open_absolute_bound_directory, open_bound_regular_file, open_or_create_private_child_dir,
    sync_parent_directory,
};

const MAX_PROPOSAL_ID_BYTES: usize = 128;
const MAX_DOCUMENT_NOTE_BODY_BYTES: usize = 256 * 1024;
const MAX_DOCUMENT_NOTE_BYTES: usize = MAX_DOCUMENT_NOTE_BODY_BYTES + 1024;
const DOCUMENTS_DIR: &str = "Documents";

/// Whether the namespace publication has a platform-supported durability
/// confirmation. A published-but-unknown outcome is an effect, never a
/// retry-safe pre-commit failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DocumentNoteDurability {
    Confirmed,
    /// The effect is live-verified through its no-follow bound file and
    /// directory bindings, but this platform cannot confirm a power-loss-safe
    /// parent-directory sync. This is normal on Windows and is distinct from
    /// a failed or invalid post-commit confirmation.
    NamespaceDurabilityUnsupported,
    /// The kernel publish may have happened but its required post-commit
    /// confirmation failed. Callers must not treat this as a normal success or
    /// a retry-safe pre-commit failure.
    PublishedDurabilityUnknown,
}

/// Evidence for one create-only user-document note publication. The note body
/// is deliberately excluded: it is user-facing untrusted text, not audit data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DocumentNoteReceipt {
    pub(crate) proposal_id: String,
    pub(crate) source_sha256: String,
    pub(crate) candidate_sha256: String,
    pub(crate) note_sha256: String,
    pub(crate) note_path: PathBuf,
    pub(crate) reconciled: bool,
    pub(crate) durability: DocumentNoteDurability,
}

struct BoundDocumentDirectoryLink {
    parent: Dir,
    name: OsString,
    dir: Dir,
    binding: BoundDirectoryChild,
    path: PathBuf,
}

struct BoundDocumentNoteTarget {
    vault: BoundDirectory,
    chain: Vec<BoundDocumentDirectoryLink>,
}

impl BoundDocumentNoteTarget {
    fn open(vault_root: &Path, subdir: &str) -> Result<Self> {
        anyhow::ensure!(
            vault_root.is_absolute(),
            "document vault must be an existing absolute path"
        );
        crate::cli::obsidian::validate_subdir(Path::new(subdir))
            .context("validate document vault subdirectory")?;
        let vault =
            open_absolute_bound_directory(vault_root, false, "operator-selected document vault")?
                .context("operator-selected document vault is missing")?;
        let mut target = Self {
            vault,
            chain: Vec::with_capacity(2),
        };
        target.open_or_create_child(OsStr::new(subdir))?;
        target.open_or_create_child(OsStr::new(DOCUMENTS_DIR))?;
        target.revalidate()?;
        Ok(target)
    }

    fn open_or_create_child(&mut self, name: &OsStr) -> Result<()> {
        let (parent, parent_path) = match self.chain.last() {
            Some(link) => (link.dir.try_clone()?, link.path.clone()),
            None => (self.vault.dir.try_clone()?, self.vault.display_path.clone()),
        };
        let path = parent_path.join(name);
        let child = open_or_create_private_child_dir(&parent, name, &path)?;
        let (dir, binding) =
            crate::skills::store::bind_retained_real_child_dir(&parent, name, &path, child)?;
        self.chain.push(BoundDocumentDirectoryLink {
            parent,
            name: name.to_os_string(),
            dir,
            binding,
            path,
        });
        Ok(())
    }

    fn documents(&self) -> &Dir {
        &self
            .chain
            .last()
            .expect("Documents link is always created")
            .dir
    }

    fn documents_path(&self) -> &Path {
        &self
            .chain
            .last()
            .expect("Documents link is always created")
            .path
    }

    fn revalidate(&self) -> Result<()> {
        self.vault
            .dir
            .dir_metadata()
            .context("inspect bound document vault")?;
        for link in &self.chain {
            link.dir.dir_metadata().with_context(|| {
                format!("inspect bound document directory {}", link.path.display())
            })?;
            anyhow::ensure!(
                link.binding
                    .matches_directory_child(&link.parent, &link.name, &link.path)?,
                "document vault child binding changed: {}",
                link.path.display(),
            );
        }
        Ok(())
    }
}

/// Publish one approved document note below `<vault>/<subdir>/Documents`.
///
/// The caller supplies hashes for the already-authorized source and candidate;
/// this helper does not read source material or create any knowledge ledger.
/// Its deterministic proposal-id filename makes an exact pre-existing file a
/// reconciled effect and any byte difference an operator-edit refusal.
pub(crate) fn apply_document_note(
    vault_root: &Path,
    subdir: &str,
    proposal_id: &str,
    source_sha256: &str,
    candidate_sha256: &str,
    note_markdown: &str,
) -> Result<DocumentNoteReceipt> {
    validate_proposal_id(proposal_id)?;
    validate_sha256("source", source_sha256)?;
    validate_sha256("candidate", candidate_sha256)?;
    let expected =
        render_document_note(proposal_id, source_sha256, candidate_sha256, note_markdown)?;
    let note_sha256 = sha256_hex(&expected);
    let name = note_file_name(proposal_id)?;
    let target = BoundDocumentNoteTarget::open(vault_root, subdir)?;
    let note_path = target.documents_path().join(&name);

    target.revalidate()?;
    match atomic_write_private_child_create_new_reported(
        target.documents(),
        &name,
        &note_path,
        &expected,
    ) {
        Ok(commit) => {
            // Publication is not reported from the rename alone. Re-open and
            // compare the exact bounded no-follow leaf before emitting a
            // receipt; a later caller may separately append WAL audit.
            verify_exact_note(&target, &name, &note_path, &expected).with_context(|| {
                format!(
                    "document note may already be published; exact post-commit verification failed: {}",
                    note_path.display()
                )
            })?;
            Ok(receipt(
                proposal_id,
                source_sha256,
                candidate_sha256,
                note_sha256,
                note_path,
                false,
                durability_from_commit(commit),
            ))
        }
        Err(error) if error_chain_has_io_kind(&error, std::io::ErrorKind::AlreadyExists) => {
            // A concurrent creator or a recovery after effect-before-audit may
            // be the same effect. Only exact bytes reconcile; a user edit,
            // symlink, substitution, or oversized target remains a refusal.
            verify_exact_note(&target, &name, &note_path, &expected)?;
            let durability = durability_from_directory_sync(sync_parent_directory(
                target.documents(),
                target.documents_path(),
            )?);
            target.revalidate()?;
            Ok(receipt(
                proposal_id,
                source_sha256,
                candidate_sha256,
                note_sha256,
                note_path,
                true,
                durability,
            ))
        }
        Err(error) => Err(error).context("publish create-only document note"),
    }
}

fn verify_exact_note(
    target: &BoundDocumentNoteTarget,
    name: &OsStr,
    path: &Path,
    expected: &[u8],
) -> Result<()> {
    target.revalidate()?;
    let actual = read_bound_note(target.documents(), name, path)?;
    anyhow::ensure!(
        actual == expected,
        "existing document note differs and is preserved: {}",
        path.display()
    );
    target.revalidate()?;
    Ok(())
}

fn read_bound_note(parent: &Dir, name: &OsStr, path: &Path) -> Result<Vec<u8>> {
    let (mut file, binding) = open_bound_regular_file(parent, name, path)?;
    let mut bytes = Vec::with_capacity(MAX_DOCUMENT_NOTE_BYTES.min(8192));
    file.by_ref()
        .take((MAX_DOCUMENT_NOTE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded document note {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= MAX_DOCUMENT_NOTE_BYTES,
        "document note exceeds bounded maximum: {}",
        path.display()
    );
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(parent, name, path)?,
        "document note binding changed while reading: {}",
        path.display()
    );
    Ok(bytes)
}

fn receipt(
    proposal_id: &str,
    source_sha256: &str,
    candidate_sha256: &str,
    note_sha256: String,
    note_path: PathBuf,
    reconciled: bool,
    durability: DocumentNoteDurability,
) -> DocumentNoteReceipt {
    DocumentNoteReceipt {
        proposal_id: proposal_id.to_owned(),
        source_sha256: source_sha256.to_owned(),
        candidate_sha256: candidate_sha256.to_owned(),
        note_sha256,
        note_path,
        reconciled,
        durability,
    }
}

fn render_document_note(
    proposal_id: &str,
    source_sha256: &str,
    candidate_sha256: &str,
    note_markdown: &str,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !note_markdown.trim().is_empty(),
        "document note body must not be empty"
    );
    anyhow::ensure!(
        note_markdown.len() <= MAX_DOCUMENT_NOTE_BODY_BYTES,
        "document note body exceeds bounded maximum"
    );
    let body_sha256 = sha256_hex(note_markdown.as_bytes());
    let note = format!(
        "---\nneoth_document_note_version: 1\nproposal_id: \"{proposal_id}\"\nsource_sha256: \"{source_sha256}\"\ncandidate_sha256: \"{candidate_sha256}\"\nbody_sha256: \"{body_sha256}\"\n---\n\n{note_markdown}"
    );
    anyhow::ensure!(
        note.len() <= MAX_DOCUMENT_NOTE_BYTES,
        "document note exceeds bounded maximum"
    );
    Ok(note.into_bytes())
}

fn note_file_name(proposal_id: &str) -> Result<OsString> {
    validate_proposal_id(proposal_id)?;
    Ok(OsString::from(format!(
        "{}.md",
        sha256_hex(proposal_id.as_bytes())
    )))
}

fn validate_proposal_id(proposal_id: &str) -> Result<()> {
    anyhow::ensure!(
        !proposal_id.is_empty()
            && proposal_id.len() <= MAX_PROPOSAL_ID_BYTES
            && proposal_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "document note proposal id must be 1..={MAX_PROPOSAL_ID_BYTES} ASCII letters, digits, '-' or '_'"
    );
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{label} SHA-256 must be lowercase hexadecimal"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn durability_from_commit(commit: PrivateChildCommit) -> DocumentNoteDurability {
    match commit {
        PrivateChildCommit::PublishedAndSynced => DocumentNoteDurability::Confirmed,
        PrivateChildCommit::PublishedDurabilityUnknown(
            PrivateChildDurabilityUnknown::ParentSyncUnsupported,
        ) => DocumentNoteDurability::NamespaceDurabilityUnsupported,
        PrivateChildCommit::PublishedDurabilityUnknown(
            PrivateChildDurabilityUnknown::ParentSyncFailed
            | PrivateChildDurabilityUnknown::PostCommitValidationFailed,
        ) => DocumentNoteDurability::PublishedDurabilityUnknown,
    }
}

fn durability_from_directory_sync(outcome: DirectorySyncOutcome) -> DocumentNoteDurability {
    match outcome {
        DirectorySyncOutcome::Confirmed => DocumentNoteDurability::Confirmed,
        DirectorySyncOutcome::Unsupported => DocumentNoteDurability::NamespaceDurabilityUnsupported,
    }
}

fn error_chain_has_io_kind(
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const SOURCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CANDIDATE: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn create_then_identical_replay_reconciles_the_same_note() {
        let vault = tempfile::tempdir().expect("vault");

        let created = apply_document_note(
            vault.path(),
            "NEOTH",
            "proposal-1",
            SOURCE,
            CANDIDATE,
            "# Approved note\n",
        )
        .expect("create note");
        let replay = apply_document_note(
            vault.path(),
            "NEOTH",
            "proposal-1",
            SOURCE,
            CANDIDATE,
            "# Approved note\n",
        )
        .expect("reconcile exact existing note");

        assert!(!created.reconciled);
        assert!(replay.reconciled);
        assert_eq!(created.note_sha256, replay.note_sha256);
        assert_eq!(created.note_path, replay.note_path);
    }

    #[test]
    fn operator_edited_note_refuses_a_replacement() {
        let vault = tempfile::tempdir().expect("vault");
        let created = apply_document_note(
            vault.path(),
            "NEOTH",
            "proposal-2",
            SOURCE,
            CANDIDATE,
            "# First\n",
        )
        .expect("create note");
        fs::write(&created.note_path, b"operator-owned edit\n").expect("edit note");

        assert!(
            apply_document_note(
                vault.path(),
                "NEOTH",
                "proposal-2",
                SOURCE,
                CANDIDATE,
                "# First\n"
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&created.note_path).expect("read operator edit"),
            b"operator-owned edit\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vault_ancestor_or_note_target_is_refused() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().expect("base");
        let real = base.path().join("real-vault");
        fs::create_dir(&real).expect("real vault");
        let linked = base.path().join("linked-vault");
        symlink(&real, &linked).expect("link vault");
        assert!(
            apply_document_note(
                &linked,
                "NEOTH",
                "proposal-3",
                SOURCE,
                CANDIDATE,
                "# Note\n"
            )
            .is_err()
        );

        let direct = base.path().join("direct-vault");
        let documents = direct.join("NEOTH").join("Documents");
        fs::create_dir_all(&documents).expect("documents");
        let target = documents.join(note_file_name("proposal-4").expect("name"));
        symlink(base.path().join("elsewhere.md"), &target).expect("link note target");
        assert!(
            apply_document_note(
                &direct,
                "NEOTH",
                "proposal-4",
                SOURCE,
                CANDIDATE,
                "# Note\n"
            )
            .is_err()
        );
    }

    #[test]
    fn oversize_existing_note_refuses_reconciliation() {
        let vault = tempfile::tempdir().expect("vault");
        let documents = vault.path().join("NEOTH").join("Documents");
        fs::create_dir_all(&documents).expect("documents");
        let target = documents.join(note_file_name("proposal-5").expect("name"));
        fs::write(&target, vec![b'x'; MAX_DOCUMENT_NOTE_BYTES + 1]).expect("oversize note");

        assert!(
            apply_document_note(
                vault.path(),
                "NEOTH",
                "proposal-5",
                SOURCE,
                CANDIDATE,
                "# Note\n"
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_provenance_or_oversize_body_never_creates_a_note() {
        let vault = tempfile::tempdir().expect("vault");
        assert!(
            apply_document_note(
                vault.path(),
                "NEOTH",
                "proposal-6",
                "not-a-hash",
                CANDIDATE,
                "# Note\n"
            )
            .is_err()
        );
        let oversized = "x".repeat(MAX_DOCUMENT_NOTE_BODY_BYTES + 1);
        assert!(
            apply_document_note(
                vault.path(),
                "NEOTH",
                "proposal-6",
                SOURCE,
                CANDIDATE,
                &oversized
            )
            .is_err()
        );
        assert!(
            !vault.path().join("NEOTH").exists(),
            "invalid input must precede vault mutation"
        );
    }

    #[test]
    fn only_unsupported_namespace_durability_is_a_live_verified_receipt_state() {
        assert_eq!(
            durability_from_commit(PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::ParentSyncUnsupported,
            )),
            DocumentNoteDurability::NamespaceDurabilityUnsupported,
        );
        assert_eq!(
            durability_from_commit(PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::ParentSyncFailed,
            )),
            DocumentNoteDurability::PublishedDurabilityUnknown,
        );
        assert_eq!(
            durability_from_commit(PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::PostCommitValidationFailed,
            )),
            DocumentNoteDurability::PublishedDurabilityUnknown,
        );
        assert_eq!(
            durability_from_directory_sync(DirectorySyncOutcome::Unsupported),
            DocumentNoteDurability::NamespaceDurabilityUnsupported,
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_namespace_limit_does_not_masquerade_as_a_post_commit_failure() {
        assert_ne!(
            durability_from_directory_sync(DirectorySyncOutcome::Unsupported),
            DocumentNoteDurability::PublishedDurabilityUnknown,
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_identical_creators_preserve_one_exact_note() {
        let vault = tempfile::tempdir().expect("vault");
        let root = vault.path().to_path_buf();
        let left = std::thread::spawn({
            let root = root.clone();
            move || apply_document_note(&root, "NEOTH", "proposal-7", SOURCE, CANDIDATE, "# Note\n")
        });
        let right = std::thread::spawn(move || {
            apply_document_note(&root, "NEOTH", "proposal-7", SOURCE, CANDIDATE, "# Note\n")
        });
        let outcomes = [
            left.join().expect("left worker"),
            right.join().expect("right worker"),
        ];
        assert!(outcomes.iter().all(|outcome| outcome.is_ok()));
        let receipts: Vec<_> = outcomes
            .into_iter()
            .map(|outcome| outcome.expect("document-note outcome"))
            .collect();
        assert_eq!(
            receipts.iter().filter(|receipt| receipt.reconciled).count(),
            1
        );
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| !receipt.reconciled)
                .count(),
            1
        );
    }
}
