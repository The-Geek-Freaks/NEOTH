//! Create-only cron quarantine records bound to a full mailbox unit and input.
//! Existing operator files and ambiguous legacy records are never replaced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::QuarantineItem;
use crate::util::atomic_write::{sync_parent_directory_required, write_private_create_new_durable};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_SCAN_BYTES: u64 = 16 * MAX_RECORD_BYTES;
const MAX_SCAN_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Created,
    AlreadyPresent,
    Conflict,
    LegacyAmbiguous,
}

#[derive(Serialize, Deserialize)]
struct Record {
    schema: String,
    input_sha256: String,
    #[serde(flatten)]
    item: QuarantineItem,
}

fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid email quarantine record",
    )
}

/// Read a bounded regular file without following the final component.
/// Writable observations allow a durable retry witness without modifying bytes.
fn read_regular(path: &Path, writable: bool) -> io::Result<Option<(File, Vec<u8>)>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || is_link(&metadata) || metadata.len() > MAX_RECORD_BYTES {
        return Err(invalid_record());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
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
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || is_link(&opened) || opened.len() > MAX_RECORD_BYTES {
        return Err(invalid_record());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid_record());
    }
    Ok(Some((file, bytes)))
}

fn observe(path: &Path, expected: &mut Record) -> Result<Option<Outcome>> {
    let (file, bytes) = match read_regular(path, true) {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return Ok(Some(Outcome::Conflict));
        }
        Err(error) => return Err(error.into()),
    };
    let observed: Record = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(Some(Outcome::Conflict)),
    };
    // Only the first successful attempt time is stable across retries. The
    // canonical byte comparison still rejects unknown/duplicate fields, edits,
    // another schema, changed findings, and input drift beyond the preview.
    expected.item.received_unix = observed.item.received_unix;
    if serde_json::to_vec_pretty(expected)? != bytes {
        return Ok(Some(Outcome::Conflict));
    }
    file.sync_all()?;
    sync_parent_directory_required(path)?;
    Ok(Some(Outcome::AlreadyPresent))
}

fn legacy_present(directory: &Path, raw_uid: &str) -> Result<bool> {
    for path in [
        super::item_path(directory, raw_uid),
        super::legacy_item_path(directory, raw_uid),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    // The legacy reader also permits renamed files. Preserve that ambiguity;
    // failed reads/parsing or an exhausted bound cannot prove absence.
    let mut bytes_read = 0u64;
    for (ordinal, entry) in fs::read_dir(directory)?.enumerate() {
        ensure!(ordinal < MAX_SCAN_ENTRIES, "quarantine scan limit reached");
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let (_, bytes) = read_regular(&path, false)?
            .ok_or_else(|| io::Error::other("quarantine changed during observation"))?;
        bytes_read += bytes.len() as u64;
        ensure!(
            bytes_read <= MAX_SCAN_BYTES,
            "quarantine byte limit reached"
        );
        let item: QuarantineItem =
            serde_json::from_slice(&bytes).context("ambiguous quarantine record")?;
        if item.uid == raw_uid {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn persist(
    home: &Path,
    item: &QuarantineItem,
    opaque_uid: &str,
    body: &str,
) -> Result<Outcome> {
    let valid = opaque_uid.strip_prefix("email-").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    ensure!(valid, "invalid mailbox-unit quarantine identity");
    let root = fs::canonicalize(home)?;
    let directory = super::quarantine_dir(&root);
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir() && !is_link(&metadata),
        "quarantine directory must not be a link or reparse point"
    );
    sync_parent_directory_required(&directory)?;
    let target = super::item_path(&directory, opaque_uid);
    let mut scoped_item = item.clone();
    scoped_item.uid = opaque_uid.to_owned();
    let mut expected = Record {
        schema: "neoth.email-quarantine.v1".into(),
        input_sha256: hex::encode(Sha256::digest(body.as_bytes())),
        item: scoped_item,
    };
    if let Some(outcome) = observe(&target, &mut expected)? {
        return Ok(outcome);
    }
    if legacy_present(&directory, &item.uid)? {
        return Ok(Outcome::LegacyAmbiguous);
    }
    let bytes = serde_json::to_vec_pretty(&expected)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "quarantine record exceeds bound"
    );
    match write_private_create_new_durable(&target, &bytes) {
        Ok(()) => Ok(Outcome::Created),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            observe(&target, &mut expected)?.ok_or_else(|| error.into())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
