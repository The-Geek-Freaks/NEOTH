//! Private archive input for a restore-owned, stopped n8n candidate.
//!
//! This module deliberately owns no lifecycle state. Its only effect is the
//! documented `docker cp - <exact-id>:/home/node/.n8n` after the exact archive
//! handle has passed a complete, bounded validation pass.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
    process::{Command as SyncCommand, Stdio},
    time::{Duration, Instant},
};

use sha2::Digest;

use super::{ManagedArchiveReceipt, valid_container_id, valid_manifest_sha256};

const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(45);
const STDERR_LIMIT: usize = 8192;

fn local_docker_host() -> &'static str {
    #[cfg(windows)]
    {
        "npipe:////./pipe/docker_engine"
    }
    #[cfg(not(windows))]
    {
        "unix:///var/run/docker.sock"
    }
}

fn archive_arguments_are_valid(
    expected_sha256: &str,
    expected_bytes: u64,
    exact_container_id: &str,
) -> bool {
    valid_manifest_sha256(expected_sha256)
        && expected_bytes > 0
        && expected_bytes <= MAX_ARCHIVE_BYTES
        && valid_container_id(exact_container_id)
}

fn safe_archive_member_path(path: &Path, entry_type: tar::EntryType) -> bool {
    let mut saw_normal = false;
    let mut saw_current_directory = false;
    for component in path.components() {
        match component {
            Component::CurDir => saw_current_directory = true,
            Component::Normal(_) => saw_normal = true,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return false,
        }
    }
    saw_normal || (saw_current_directory && entry_type.is_dir())
}

struct ArchiveReader {
    file: File,
    hasher: sha2::Sha256,
    bytes: u64,
    max_bytes: u64,
    read_error: Option<&'static str>,
}

impl ArchiveReader {
    fn new(file: File, max_bytes: u64) -> Self {
        Self {
            file,
            hasher: sha2::Sha256::new(),
            bytes: 0,
            max_bytes,
            read_error: None,
        }
    }

    fn receipt(&self) -> ManagedArchiveReceipt {
        let hasher = self.hasher.clone();
        ManagedArchiveReceipt {
            archive_sha256: format!("{:x}", hasher.finalize()),
            archive_bytes: self.bytes,
        }
    }

    fn rewind(&mut self) -> Result<(), &'static str> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "n8n_restore_archive_seek_failed")?;
        Ok(())
    }
}

impl Read for ArchiveReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = match self.file.read(buffer) {
            Ok(count) => count,
            Err(error) => {
                self.read_error = Some("n8n_restore_archive_read_failed");
                return Err(error);
            }
        };
        let count_u64 = match u64::try_from(count) {
            Ok(count) => count,
            Err(_) => {
                self.read_error = Some("n8n_restore_archive_size_invalid");
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        };
        let next_bytes = match self.bytes.checked_add(count_u64) {
            Some(next_bytes) => next_bytes,
            None => {
                self.read_error = Some("n8n_restore_archive_limit_exceeded");
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
        };
        if next_bytes > self.max_bytes {
            self.read_error = Some("n8n_restore_archive_limit_exceeded");
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        if count != 0 {
            self.hasher.update(&buffer[..count]);
            self.bytes = next_bytes;
        }
        Ok(count)
    }
}

fn drain_zero_padding(reader: &mut ArchiveReader) -> Result<(), &'static str> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| {
            reader
                .read_error
                .unwrap_or("n8n_restore_archive_tar_invalid")
        })?;
        if count == 0 {
            return Ok(());
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err("n8n_restore_archive_trailing_data");
        }
    }
}

fn validate_open_archive(
    file: File,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<ArchiveReader, &'static str> {
    let mut reader = ArchiveReader::new(file, expected_bytes);
    let validation = (|| -> Result<(), &'static str> {
        let mut archive = tar::Archive::new(&mut reader);
        let entries = archive
            .entries()
            .map_err(|_| "n8n_restore_archive_tar_invalid")?;
        for entry in entries {
            let mut entry = entry.map_err(|_| "n8n_restore_archive_tar_invalid")?;
            let entry_type = entry.header().entry_type();
            if !entry_type.is_file() && !entry_type.is_dir() {
                return Err("n8n_restore_archive_unsafe_member");
            }
            let path = entry
                .path()
                .map_err(|_| "n8n_restore_archive_unsafe_member")?;
            if !safe_archive_member_path(&path, entry_type) {
                return Err("n8n_restore_archive_unsafe_member");
            }
            std::io::copy(&mut entry, &mut std::io::sink())
                .map_err(|_| "n8n_restore_archive_tar_invalid")?;
        }
        Ok(())
    })();
    validation.map_err(|error| reader.read_error.unwrap_or(error))?;
    drain_zero_padding(&mut reader)?;
    let receipt = reader.receipt();
    if receipt.archive_bytes != expected_bytes || receipt.archive_sha256 != expected_sha256 {
        return Err("n8n_restore_archive_mismatch");
    }
    reader.rewind()?;
    Ok(reader)
}

fn open_private_regular_archive(archive: &Path, expected_bytes: u64) -> Result<File, &'static str> {
    let metadata = std::fs::symlink_metadata(archive).map_err(|_| "n8n_restore_archive_missing")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != expected_bytes
    {
        return Err("n8n_restore_archive_mismatch");
    }
    #[cfg(windows)]
    let file = File::open(archive).map_err(|_| "n8n_restore_archive_read_failed")?;
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(&file)
        .map_err(|_| "n8n_restore_archive_private_handle_invalid")?;
    #[cfg(not(windows))]
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        options
            .open(archive)
            .map_err(|_| "n8n_restore_archive_read_failed")?
    };
    let opened = file
        .metadata()
        .map_err(|_| "n8n_restore_archive_read_failed")?;
    if !opened.is_file() || opened.len() != expected_bytes {
        return Err("n8n_restore_archive_mismatch");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            return Err("n8n_restore_archive_private_handle_invalid");
        }
    }
    Ok(file)
}

fn drain_limited<R: Read>(mut reader: R) -> Result<bool, &'static str> {
    let mut retained = 0usize;
    let mut overflow = false;
    let mut buffer = [0_u8; 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| "n8n_restore_docker_stderr_failed")?;
        if count == 0 {
            return Ok(overflow);
        }
        let remaining = STDERR_LIMIT.saturating_sub(retained);
        retained += count.min(remaining);
        overflow |= count > remaining;
    }
}

fn stream_open_archive_to_stdin(
    mut archive: ArchiveReader,
    mut stdin: impl Write,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<ManagedArchiveReceipt, &'static str> {
    let mut hasher = sha2::Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = archive
            .file
            .read(&mut buffer)
            .map_err(|_| "n8n_restore_archive_read_failed")?;
        if count == 0 {
            break;
        }
        let count_u64 = u64::try_from(count).map_err(|_| "n8n_restore_archive_size_invalid")?;
        bytes = bytes
            .checked_add(count_u64)
            .ok_or("n8n_restore_archive_limit_exceeded")?;
        if bytes > expected_bytes {
            return Err("n8n_restore_archive_input_drift");
        }
        stdin
            .write_all(&buffer[..count])
            .map_err(|_| "n8n_restore_docker_stdin_failed")?;
        hasher.update(&buffer[..count]);
    }
    stdin
        .flush()
        .map_err(|_| "n8n_restore_docker_stdin_failed")?;
    let receipt = ManagedArchiveReceipt {
        archive_sha256: format!("{:x}", hasher.finalize()),
        archive_bytes: bytes,
    };
    if receipt.archive_bytes != expected_bytes || receipt.archive_sha256 != expected_sha256 {
        return Err("n8n_restore_archive_input_drift");
    }
    Ok(receipt)
}

fn extract_private_archive_to_exact_container_sync(
    archive: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    exact_container_id: &str,
) -> Result<ManagedArchiveReceipt, &'static str> {
    if !archive_arguments_are_valid(expected_sha256, expected_bytes, exact_container_id) {
        return Err("n8n_restore_archive_arguments_invalid");
    }
    let file = open_private_regular_archive(archive, expected_bytes)?;
    let archive = validate_open_archive(file, expected_sha256, expected_bytes)?;
    let expected_sha256 = expected_sha256.to_owned();

    let destination = format!("{exact_container_id}:/home/node/.n8n");
    let mut child = SyncCommand::new("docker")
        .arg("--host")
        .arg(local_docker_host())
        .args(["cp", "-", &destination])
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "n8n_restore_docker_spawn_failed")?;
    let stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("n8n_restore_docker_stdin_failed");
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("n8n_restore_docker_stderr_failed");
        }
    };
    let (stream_tx, stream_rx) = std::sync::mpsc::sync_channel(1);
    let stream_thread = std::thread::spawn(move || {
        let _ = stream_tx.send(stream_open_archive_to_stdin(
            archive,
            stdin,
            &expected_sha256,
            expected_bytes,
        ));
    });
    let stderr_thread = std::thread::spawn(move || drain_limited(stderr));
    let deadline = Instant::now() + DEADLINE;
    let mut stream_result = None;
    let status = loop {
        if stream_result.is_none() {
            match stream_rx.try_recv() {
                Ok(result) => {
                    if result.is_err() {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = stream_thread.join();
                        let _ = stderr_thread.join();
                        return result;
                    }
                    stream_result = Some(result);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stream_thread.join();
                    let _ = stderr_thread.join();
                    return Err("n8n_restore_docker_stdin_failed");
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stream_thread.join();
                let _ = stderr_thread.join();
                return Err("n8n_restore_docker_wait_failed");
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stream_thread.join();
                let _ = stderr_thread.join();
                return Err("n8n_restore_docker_timeout");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let receipt = stream_result.unwrap_or_else(|| {
        stream_rx
            .recv()
            .unwrap_or(Err("n8n_restore_docker_stdin_failed"))
    })?;
    stream_thread
        .join()
        .map_err(|_| "n8n_restore_docker_stdin_failed")?;
    let stderr_overflow = stderr_thread
        .join()
        .map_err(|_| "n8n_restore_docker_stderr_failed")??;
    if stderr_overflow {
        return Err("n8n_restore_docker_stderr_limit");
    }
    if !status.success() {
        return Err("n8n_restore_docker_command_failed");
    }
    Ok(receipt)
}

/// Validates the complete private archive before it spawns Docker, then copies
/// the same opened file handle to a stopped, receipt-witnessed candidate.
pub(super) async fn extract_private_archive_to_exact_container(
    archive: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    exact_container_id: &str,
) -> Result<ManagedArchiveReceipt, &'static str> {
    let archive = archive.to_owned();
    let expected_sha256 = expected_sha256.to_owned();
    let exact_container_id = exact_container_id.to_owned();
    tokio::task::spawn_blocking(move || {
        extract_private_archive_to_exact_container_sync(
            &archive,
            &expected_sha256,
            expected_bytes,
            &exact_container_id,
        )
    })
    .await
    .map_err(|_| "n8n_restore_docker_wait_failed")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn regular_tar_bytes() -> Vec<u8> {
        let payload = b"restored sqlite bytes";
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o600);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "database.sqlite", &payload[..])
                .expect("regular entry");
            builder.finish().expect("tar finish");
        }
        bytes
    }

    fn private_archive_file(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let archive = home.path().join("restore.tar");
        std::fs::write(&archive, bytes).expect("archive write");
        let digest = format!("{:x}", sha2::Sha256::digest(bytes));
        (home, archive, digest)
    }

    fn symlink_tar_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o600);
            builder
                .append_link(
                    &mut header,
                    "outside.sqlite",
                    "/outside-volume/database.sqlite",
                )
                .expect("link entry");
            builder.finish().expect("tar finish");
        }
        bytes
    }

    #[test]
    fn restore_contract_rejects_invalid_identity_digest_and_bounds() {
        assert!(!archive_arguments_are_valid(
            "A".repeat(64).as_str(),
            1,
            &"a".repeat(64)
        ));
        assert!(!archive_arguments_are_valid(
            &"a".repeat(64),
            0,
            &"a".repeat(64)
        ));
        assert!(!archive_arguments_are_valid(
            &"a".repeat(64),
            MAX_ARCHIVE_BYTES + 1,
            &"a".repeat(64)
        ));
        assert!(!archive_arguments_are_valid(&"a".repeat(64), 1, "wrong-id"));
        assert!(archive_arguments_are_valid(
            &"a".repeat(64),
            1,
            &"b".repeat(64)
        ));
    }

    #[test]
    fn restore_validation_hashes_entire_regular_archive_and_rewinds_same_handle() {
        let bytes = regular_tar_bytes();
        let (_home, archive, digest) = private_archive_file(&bytes);
        let file = File::open(&archive).expect("single test handle");
        let mut reader =
            validate_open_archive(file, &digest, bytes.len() as u64).expect("valid archive");
        assert_eq!(reader.receipt().archive_bytes, bytes.len() as u64);
        let mut replay = Vec::new();
        reader
            .file
            .read_to_end(&mut replay)
            .expect("same handle replay");
        assert_eq!(replay, bytes);
    }

    #[test]
    fn restore_validation_rejects_trailing_data_before_docker() {
        let mut bytes = regular_tar_bytes();
        bytes.extend_from_slice(b"unexpected-data");
        let (_home, archive, digest) = private_archive_file(&bytes);
        let file = File::open(&archive).expect("single test handle");
        assert!(matches!(
            validate_open_archive(file, &digest, bytes.len() as u64),
            Err("n8n_restore_archive_trailing_data")
        ));
    }

    #[test]
    fn restore_validation_rejects_symlinked_archive_member_before_docker() {
        let bytes = symlink_tar_bytes();
        let (_home, archive, digest) = private_archive_file(&bytes);
        let file = File::open(&archive).expect("single test handle");
        assert!(matches!(
            validate_open_archive(file, &digest, bytes.len() as u64),
            Err("n8n_restore_archive_unsafe_member")
        ));
    }
}
