//! Cron-only, account-bound email notes. Existing notes are never replaced.
//!
//! Exact deterministic bytes are the local completion witness. Interrupted or
//! edited files conflict; legacy names are not adopted or silently duplicated.
//! This does not migrate the shared legacy email seen-state ledger.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::security::paperless_ingest::PaperlessOcrPayload;
use crate::util::atomic_write::{sync_parent_directory_required, write_private_create_new_durable};

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

fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn note_directory(vault_root: &Path, subdir: &str) -> io::Result<PathBuf> {
    let relative = Path::new(subdir);
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid_path());
    }
    // Resolve the configured root once; descendants must be ordinary directories.
    let mut directory = fs::canonicalize(vault_root)?;
    if !directory.is_dir() {
        return Err(invalid_path());
    }
    for part in relative
        .components()
        .chain(Path::new("Paperless").components())
    {
        directory.push(part.as_os_str());
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || is_link(&metadata) {
            return Err(invalid_path());
        }
        // Also finish a directory commit interrupted during an earlier attempt.
        sync_parent_directory_required(&directory)?;
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
fn observe_existing(path: &Path, expected: &[u8]) -> io::Result<Option<EmailNoteOutcome>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || is_link(&metadata) || metadata.len() != expected.len() as u64 {
        return Ok(Some(EmailNoteOutcome::Conflict));
    }
    // Write permission is needed for a durable sync on Windows; no bytes are
    // written and no truncate/create flag is set.
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file: File = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || is_link(&opened) {
        return Ok(Some(EmailNoteOutcome::Conflict));
    }
    let mut observed = Vec::with_capacity(expected.len());
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    if observed != expected {
        return Ok(Some(EmailNoteOutcome::Conflict));
    }
    file.sync_all()?;
    sync_parent_directory_required(path)?;
    Ok(Some(EmailNoteOutcome::AlreadyPresent))
}

pub(crate) fn sync_email_to_obsidian(
    payload: &PaperlessOcrPayload,
    input_text: &str,
    legacy_doc_id: &str,
    vault_root: &Path,
    subdir: &str,
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
    let target = directory.join(format!("{}.md", payload.document_id));
    let rendition = render_email_note(payload, input_text);
    if let Some(outcome) = observe_existing(&target, rendition.as_bytes())? {
        return Ok(outcome);
    }
    // The old lossy name cannot prove which account or unit owns its bytes.
    // Existence, even of a broken link or directory, prevents a second note.
    let legacy = directory.join(format!("{legacy_doc_id}.md"));
    match fs::symlink_metadata(&legacy) {
        Ok(_) => return Ok(EmailNoteOutcome::LegacyAmbiguous),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match write_private_create_new_durable(&target, rendition.as_bytes()) {
        Ok(()) => Ok(EmailNoteOutcome::Created),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            observe_existing(&target, rendition.as_bytes())?.ok_or(error)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
