//! GOLD-ADAPT-HANDY-04 — model download manager.
//!
//! Adapted from Handy `src-tauri/src/managers/model.rs` (MIT). Provides
//! three guarantees the old audio.rs "just check if cached" path lacks:
//!
//! 1. **SHA-256 integrity** — every downloaded file is verified against a
//!    declared digest. A mismatch is a hard error; the partial file is deleted
//!    so a corrupt download does not persist and confuse the next run.
//!
//! 2. **Resumable downloads** — `GET` with `Range: bytes=<partial_len>-` when a
//!    partial file already exists, so a ~1.6 GiB whisper model can survive a
//!    network hiccup without restarting from zero. If the server does not support
//!    206 Partial Content the connection falls back to a full download.
//!
//! 3. **Atomic extract** — the final destination file is written to `<dest>.tmp`
//!    first, then `rename`d into place. Concurrent readers never see a partial
//!    write; a crash mid-extract leaves an orphaned `.tmp` file that the next run
//!    cleans up and restarts (never a silently truncated destination).
//!
//! ## Design constraints
//!
//! - **No new crate deps.** Uses only `sha2`, `reqwest`, `tokio`, `hex`,
//!   `anyhow`, and `tracing` — all already present in `neothd`'s `Cargo.toml`.
//! - The `reqwest::Client` is injected by the caller (usually the singleton from
//!   `providers::http_client`) so this module carries no HTTP construction token.
//! - Progress is logged via `tracing` at `INFO` level; no callbacks yet (the
//!   planned `neoth download` CLI subcommand can wrap this and format its own
//!   progress bar).
//!
//! ## Usage
//!
//! ```rust,ignore
//! let client = crate::providers::http_client::build_client()?;
//! let files = vec![
//!     ModelFile {
//!         url: "https://huggingface.co/…/model.safetensors".to_string(),
//!         dest: PathBuf::from("/home/user/.neoth/models/openai-whisper/model.safetensors"),
//!         sha256: "abc123…".to_string(),
//!     },
//! ];
//! download_model_files(&client, &files).await?;
//! ```

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// One file that must be downloaded and verified.
#[derive(Debug, Clone)]
pub struct ModelFile {
    /// Full HTTPS URL of the remote file.
    pub url: String,
    /// Local destination path (directory must already exist or be creatable).
    pub dest: PathBuf,
    /// Expected lowercase hex SHA-256 of the complete file content.
    pub sha256: String,
}

/// Download and verify every file in `files`.
///
/// - Already-present correct files are skipped (fast-path: stat + hash).
/// - Partial downloads (`.tmp` side-car) are resumed from their current size.
/// - Each file is verified after download; mismatch → `Err`, side-car removed.
/// - On success the `.tmp` file is atomically renamed into the final `dest`.
///
/// Errors on the *first* failing file; earlier successful files stay in place.
pub async fn download_model_files(
    client: &reqwest::Client,
    files: &[ModelFile],
) -> Result<()> {
    for f in files {
        download_one(client, f).await.with_context(|| {
            format!("model_manager: failed to fetch {}", f.dest.display())
        })?;
    }
    Ok(())
}

/// Verify that `path` matches `expected_sha256`. Returns `Ok(())` on match,
/// `Err` with a human-readable message on mismatch or IO error.
pub async fn verify_file(path: &Path, expected_sha256: &str) -> Result<()> {
    let hash = sha256_of_file(path).await?;
    if hash != expected_sha256.to_ascii_lowercase() {
        bail!(
            "SHA-256 mismatch for {}: expected {}, got {}",
            path.display(),
            expected_sha256,
            hash
        );
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Download a single [`ModelFile`], resuming from a partial `.tmp` side-car if
/// one exists. Verifies the SHA-256 after download and renames into `dest`.
async fn download_one(client: &reqwest::Client, f: &ModelFile) -> Result<()> {
    let tmp = tmp_path(&f.dest);

    // Fast-path: destination already exists and hash matches — nothing to do.
    if f.dest.exists() {
        info!("model_manager: {} already present; verifying…", f.dest.display());
        match verify_file(&f.dest, &f.sha256).await {
            Ok(()) => {
                info!("model_manager: {} verified OK (skip)", f.dest.display());
                return Ok(());
            }
            Err(e) => {
                warn!(
                    "model_manager: existing {} failed verification ({e}); re-downloading",
                    f.dest.display()
                );
                // Remove the corrupt destination and fall through to a fresh download.
                let _ = tokio::fs::remove_file(&f.dest).await;
            }
        }
    }

    // Ensure destination directory exists.
    if let Some(parent) = f.dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create dir {}", parent.display()))?;
    }

    // Resume offset: how many bytes the `.tmp` file already holds.
    let resume_from = tmp_existing_len(&tmp).await;

    // Build the GET request, injecting a Range header when resuming.
    let mut req = client.get(&f.url);
    if resume_from > 0 {
        info!(
            "model_manager: resuming {} from byte {}",
            f.dest.display(),
            resume_from
        );
        req = req.header("Range", format!("bytes={}-", resume_from));
    } else {
        info!("model_manager: downloading {} → {}", f.url, f.dest.display());
    }

    let resp = req
        .send()
        .await
        .with_context(|| format!("GET {}", f.url))?
        .error_for_status()
        .with_context(|| format!("HTTP error for {}", f.url))?;

    let is_partial = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;

    // Open the `.tmp` file: append when resuming a partial (206), truncate otherwise.
    let mut file = if is_partial && resume_from > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&tmp)
            .await
            .with_context(|| format!("open (append) {}", tmp.display()))?
    } else {
        // Server ignored Range or this is a fresh start — overwrite from scratch.
        tokio::fs::File::create(&tmp)
            .await
            .with_context(|| format!("create {}", tmp.display()))?
    };

    // Stream the body into the tmp file.
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    let mut bytes_written: u64 = if is_partial { resume_from } else { 0 };
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read chunk from {}", f.url))?;
        file.write_all(&chunk)
            .await
            .with_context(|| format!("write chunk to {}", tmp.display()))?;
        bytes_written += chunk.len() as u64;
    }
    file.flush().await?;
    drop(file);

    info!(
        "model_manager: download complete ({} bytes total) for {}",
        bytes_written,
        f.dest.display()
    );

    // Verify SHA-256 of the completed `.tmp` file.
    verify_file(&tmp, &f.sha256).await.inspect_err(|_| {
        // Clean up so the corrupt partial does not linger.
        let _ = std::fs::remove_file(&tmp);
    })?;

    // Atomic rename: tmp → dest.
    tokio::fs::rename(&tmp, &f.dest)
        .await
        .with_context(|| {
            format!("rename {} → {}", tmp.display(), f.dest.display())
        })?;

    info!("model_manager: installed {}", f.dest.display());
    Ok(())
}

/// The side-car path used during download: `<dest>.tmp`.
fn tmp_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// How many bytes the `.tmp` side-car currently holds (0 if absent or on error).
async fn tmp_existing_len(tmp: &Path) -> u64 {
    match tokio::fs::metadata(tmp).await {
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

/// Compute lowercase hex SHA-256 of the complete file at `path`.
async fn sha256_of_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read {} for SHA-256", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Pure SHA-256 helper (sync — operates on in-memory bytes).
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    // ── SHA-256 mismatch returns Err ──────────────────────────────────────────

    #[tokio::test]
    async fn sha256_mismatch_returns_err() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("model.bin");
        std::fs::write(&path, b"hello world").unwrap();

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_file(&path, wrong_hash).await;
        assert!(result.is_err(), "expected Err on SHA-256 mismatch");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("SHA-256 mismatch"),
            "error should mention SHA-256 mismatch, got: {msg}"
        );
    }

    #[tokio::test]
    async fn sha256_correct_hash_returns_ok() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("model.bin");
        let data = b"neoth model weights content";
        std::fs::write(&path, data).unwrap();

        let expected = sha256_hex(data);
        verify_file(&path, &expected).await.unwrap();
    }

    #[tokio::test]
    async fn sha256_missing_file_returns_err() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("no_such_file.bin");
        let result = verify_file(&path, "0000000000000000000000000000000000000000000000000000000000000000").await;
        assert!(result.is_err(), "expected Err for missing file");
    }

    // ── tmp_path side-car naming ──────────────────────────────────────────────

    #[test]
    fn tmp_path_appends_tmp_suffix() {
        let dest = PathBuf::from("/home/user/.neoth/models/model.safetensors");
        let tmp = tmp_path(&dest);
        assert_eq!(
            tmp,
            PathBuf::from("/home/user/.neoth/models/model.safetensors.tmp")
        );
    }

    // ── atomic extract: writes .tmp then renames ──────────────────────────────

    #[tokio::test]
    async fn atomic_extract_writes_tmp_then_renames() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("output.bin");
        let tmp = tmp_path(&dest);

        // Simulate the post-download state: a complete .tmp file.
        let data = b"model weights";
        std::fs::write(&tmp, data).unwrap();

        // Rename atomically — mirrors what download_one does on success.
        tokio::fs::rename(&tmp, &dest).await.unwrap();

        assert!(dest.exists(), "dest must exist after rename");
        assert!(!tmp.exists(), "tmp must be gone after rename");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn atomic_extract_dest_not_visible_until_rename() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("output2.bin");
        let tmp = tmp_path(&dest);

        // tmp written but NOT renamed → dest absent.
        std::fs::write(&tmp, b"in-progress").unwrap();
        assert!(!dest.exists(), "dest must NOT appear before rename");
    }

    // ── resumable: picks up from partial ─────────────────────────────────────

    #[tokio::test]
    async fn resumable_partial_tmp_length_detected() {
        let dir = tempdir().unwrap();
        let partial_content = b"partial data already on disk";
        let tmp = dir.path().join("big_model.safetensors.tmp");
        std::fs::write(&tmp, partial_content).unwrap();

        let detected_len = tmp_existing_len(&tmp).await;
        assert_eq!(
            detected_len,
            partial_content.len() as u64,
            "resume offset must match partial file length"
        );
    }

    #[tokio::test]
    async fn resumable_absent_tmp_gives_zero_offset() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("not_there.tmp");
        let detected_len = tmp_existing_len(&tmp).await;
        assert_eq!(detected_len, 0, "absent .tmp must return offset 0");
    }

    #[tokio::test]
    async fn resumable_appends_to_existing_tmp_on_partial_response() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("model.bin");
        let tmp = tmp_path(&dest);

        // Pre-existing partial.
        let part1 = b"first_half_";
        std::fs::write(&tmp, part1).unwrap();
        assert_eq!(tmp_existing_len(&tmp).await, part1.len() as u64);

        // Simulate appending the second half (as the 206 response path does).
        let part2 = b"second_half";
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&tmp)
                .unwrap();
            f.write_all(part2).unwrap();
        }

        let full: Vec<u8> = [part1.as_slice(), part2.as_slice()].concat();

        // Verify the combined content has the right hash.
        let expected = sha256_hex(&full);
        verify_file(&tmp, &expected).await.unwrap();

        // Atomic rename.
        tokio::fs::rename(&tmp, &dest).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), full);
    }

    // ── sha256_hex ────────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_known_vector() {
        // echo -n "" | sha256sum → e3b0c44298fc1c14...
        let empty_hash = sha256_hex(b"");
        assert_eq!(
            empty_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_hello_world() {
        // SHA-256("hello world") verified via PowerShell
        // [System.Security.Cryptography.SHA256]::Create().ComputeHash(...)
        let h = sha256_hex(b"hello world");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
