//! Cron-only, account-bound email notes. Existing notes are never replaced.
//!
//! Exact deterministic bytes are the local completion witness. Interrupted or
//! edited files conflict; legacy names are not adopted or silently duplicated.
//! This does not migrate the shared legacy email seen-state ledger.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use cap_std::fs::Dir;
use sha2::{Digest, Sha256};

use crate::security::paperless_ingest::PaperlessOcrPayload;
use crate::skills::store::{self, BoundDirectory, BoundDirectoryChild, PrivateChildCommit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmailNoteOutcome {
    Created,
    AlreadyPresent,
    Conflict,
    LegacyAmbiguous,
}

fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid email note identity or path",
    )
}

fn store_error(error: anyhow::Error) -> io::Error {
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>().map(io::Error::kind))
        .unwrap_or(io::ErrorKind::Other);
    io::Error::new(kind, error)
}

struct NoteChildDirectory {
    dir: Dir,
    binding: BoundDirectoryChild,
    name: OsString,
    path: PathBuf,
}

struct NoteDirectory {
    anchor: BoundDirectory,
    children: Vec<NoteChildDirectory>,
}

impl NoteDirectory {
    fn current(&self) -> (&Dir, &Path) {
        self.children.last().map_or(
            (&self.anchor.dir, self.anchor.display_path.as_path()),
            |child| (&child.dir, child.path.as_path()),
        )
    }

    fn revalidate(&self) -> io::Result<()> {
        let mut parent = &self.anchor.dir;
        for child in &self.children {
            if !child
                .binding
                .matches_directory_child(parent, &child.name, &child.path)
                .map_err(store_error)?
            {
                return Err(io::Error::other("email note directory identity changed"));
            }
            parent = &child.dir;
        }
        Ok(())
    }

    fn descend(&mut self, name: &OsStr, create: bool) -> io::Result<()> {
        self.revalidate()?;
        let (parent, parent_path) = self.current();
        let path = parent_path.join(name);
        let (dir, binding) = if create {
            let child = store::open_or_create_private_child_dir(parent, name, &path)
                .map_err(store_error)?;
            store::bind_retained_real_child_dir(parent, name, &path, child)
        } else {
            store::open_bound_real_child_dir(parent, name, &path)
        }
        .map_err(store_error)?;
        self.children.push(NoteChildDirectory {
            dir,
            binding,
            name: name.to_os_string(),
            path,
        });
        self.revalidate()
    }
}

fn note_directory(vault_root: &Path, subdir: &str) -> io::Result<NoteDirectory> {
    let relative = Path::new(subdir);
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid_path());
    }
    // The configured root is resolved once. Its parent is the trusted anchor;
    // the root and every descendant retain direct-child identity fences.
    let root = fs::canonicalize(vault_root)?;
    let anchor_path = root.parent().unwrap_or(&root);
    let anchor = store::open_absolute_bound_directory(anchor_path, false, "email vault parent")
        .map_err(store_error)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "email vault parent is absent"))?;
    let mut directory = NoteDirectory {
        anchor,
        children: Vec::new(),
    };
    if let Some(name) = root.file_name() {
        directory.descend(name, false)?;
    }
    for part in relative
        .components()
        .chain(Path::new("Paperless").components())
    {
        directory.descend(part.as_os_str(), true)?;
    }
    Ok(directory)
}

fn render_email_note(payload: &PaperlessOcrPayload, input_text: &str) -> String {
    // Attempt timestamps are deliberately absent: retrying the same unit must
    // compare identical bytes. The full pre-OCR input digest detects drift even
    // when sanitization produces the same rendered body.
    let input_sha256 = hex::encode(Sha256::digest(input_text.as_bytes()));
    format!(
        "---\n\
         doc_id: \"{id}\"\n\
         note_schema: \"neoth.email-vault.v1\"\n\
         input_sha256: \"{input_sha256}\"\n\
         ocr_source: \"{source}\"\n\
         raw_input_hash: \"{raw_hash}\"\n\
         sanitizer_findings_count: {count}\n\
         ---\n\n\
         # Paperless document {id}\n\n\
         ## Body\n\n\
         {body}\n\n\
         ## Sanitizer findings\n\n\
         {findings}",
        id = payload.document_id,
        source = payload.source.as_str(),
        raw_hash = super::escape_yaml_string(&payload.raw_input_hash),
        count = payload.findings.len(),
        body = payload.body().trim_end_matches('\n'),
        findings = super::render_findings_block(&payload.findings),
    )
}

/// None means absent; matching bytes must also be synced before completion.
/// Comparison is bounded by the expected rendition, including a trailing-byte
/// check. Local concurrent edits can invalidate the note after this observation.
fn observe_existing(
    directory: &NoteDirectory,
    name: &OsStr,
    expected: &[u8],
    observe: &mut impl FnMut(NoteObservation),
) -> io::Result<Option<EmailNoteOutcome>> {
    directory.revalidate()?;
    let (parent, parent_path) = directory.current();
    let path = parent_path.join(name);
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || store::cap_metadata_is_link_like(&metadata)
        || metadata.len() != expected.len() as u64
    {
        return Ok(Some(EmailNoteOutcome::Conflict));
    }
    // Write permission is needed for a durable sync on Windows; no bytes are
    // written and no truncate/create flag is set.
    let (mut file, binding) =
        store::open_bound_regular_file_readwrite(parent, name, &path).map_err(store_error)?;
    let mut observed = Vec::with_capacity(expected.len());
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    if observed != expected {
        return Ok(Some(EmailNoteOutcome::Conflict));
    }
    observe(NoteObservation::ExistingRead);
    file.sync_all()?;
    // Match the existing platform contract: POSIX requires directory fsync;
    // Windows creation uses the existing private write-through publication.
    store::sync_parent_directory(parent, parent_path).map_err(store_error)?;
    if !binding
        .matches_regular_file_child_readonly(parent, name, &path)
        .map_err(store_error)?
    {
        return Err(io::Error::other("email note file identity changed"));
    }
    directory.revalidate()?;
    Ok(Some(EmailNoteOutcome::AlreadyPresent))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NoteObservation {
    DirectoryBound,
    BeforeCreate,
    Created,
    ExistingRead,
}

pub(crate) fn sync_email_to_obsidian(
    payload: &PaperlessOcrPayload,
    input_text: &str,
    legacy_doc_id: &str,
    vault_root: &Path,
    subdir: &str,
) -> io::Result<EmailNoteOutcome> {
    sync_email_to_obsidian_observed(
        payload,
        input_text,
        legacy_doc_id,
        vault_root,
        subdir,
        |_| {},
    )
}

fn sync_email_to_obsidian_observed(
    payload: &PaperlessOcrPayload,
    input_text: &str,
    legacy_doc_id: &str,
    vault_root: &Path,
    subdir: &str,
    mut observe: impl FnMut(NoteObservation),
) -> io::Result<EmailNoteOutcome> {
    let valid_unit = payload
        .document_id
        .strip_prefix("email-")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    if !valid_unit || !super::is_safe_doc_id(legacy_doc_id) {
        return Err(invalid_path());
    }
    let directory = note_directory(vault_root, subdir)?;
    observe(NoteObservation::DirectoryBound);
    directory.revalidate()?;
    let (parent, parent_path) = directory.current();
    let name = OsString::from(format!("{}.md", payload.document_id));
    let target = parent_path.join(&name);
    let rendition = render_email_note(payload, input_text);
    if let Some(outcome) = observe_existing(&directory, &name, rendition.as_bytes(), &mut observe)?
    {
        return Ok(outcome);
    }
    // The old lossy name cannot prove which account or unit owns its bytes.
    // Existence, even of a broken link or directory, prevents a second note.
    let legacy = OsString::from(format!("{legacy_doc_id}.md"));
    match parent.symlink_metadata(&legacy) {
        Ok(_) => return Ok(EmailNoteOutcome::LegacyAmbiguous),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    observe(NoteObservation::BeforeCreate);
    directory.revalidate()?;
    match store::atomic_write_private_child_create_new_reported(
        parent,
        &name,
        &target,
        rendition.as_bytes(),
    ) {
        Ok(PrivateChildCommit::PublishedAndSynced) => {
            observe(NoteObservation::Created);
            match observe_existing(&directory, &name, rendition.as_bytes(), &mut observe)? {
                Some(EmailNoteOutcome::AlreadyPresent) => Ok(EmailNoteOutcome::Created),
                Some(outcome) => Ok(outcome),
                None => Err(io::Error::other("published email note is absent")),
            }
        }
        Ok(PrivateChildCommit::PublishedDurabilityUnknown(reason)) => Err(io::Error::other(reason)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
        {
            observe_existing(&directory, &name, rendition.as_bytes(), &mut observe)?
                .ok_or_else(|| io::Error::other(error))
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

#[cfg(test)]
mod tests;
