//! ADOPT31-F4 — pinned managed yt-dlp binary.
//!
//! The binary comes only from a standalone tagged upstream GitHub release asset
//! selected for the current supported OS/architecture. A floating package
//! manager or pip install is intentionally not offered: caption parsing is
//! executable-code input and must stay pinned.

use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use tokio::process::Command;

pub const YT_DLP_VERSION: &str = "2026.08.19";
const MAX_INSTALL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformAsset {
    remote_name: &'static str,
    sha256: &'static str,
}

impl PlatformAsset {
    pub const fn remote_name(self) -> &'static str {
        self.remote_name
    }
    pub const fn sha256(self) -> &'static str {
        self.sha256
    }
}

pub const fn asset_name() -> &'static str {
    if cfg!(windows) {
        "yt-dlp.exe"
    } else {
        "yt-dlp"
    }
}

pub fn platform_asset() -> Result<PlatformAsset> {
    platform_asset_for(std::env::consts::OS, std::env::consts::ARCH)
}

fn platform_asset_for(os: &str, arch: &str) -> Result<PlatformAsset> {
    let asset = match (os, arch) {
        ("windows", "x86_64") => PlatformAsset {
            remote_name: "yt-dlp.exe",
            sha256: "66674953fe251b89f4d08c5f0e35e0728679bd67ab3d7d05c0562af101dd3e7a",
        },
        ("windows", "aarch64") => PlatformAsset {
            remote_name: "yt-dlp_arm64.exe",
            sha256: "05b438997bafc3affdfda9d041353c9d73e04dc842207254b655b0887c4445b0",
        },
        ("linux", "x86_64") => PlatformAsset {
            remote_name: "yt-dlp_linux",
            sha256: "58162f9bfdc27458ea47bfcb311cf47028f17d8154a8bf7d689861d46399230a",
        },
        ("linux", "aarch64") => PlatformAsset {
            remote_name: "yt-dlp_linux_aarch64",
            sha256: "b16e4dab368a816cd05d477d698a605a6ae87ccee1c8ffd38fa21d7254141fcc",
        },
        ("macos", "x86_64" | "aarch64") => PlatformAsset {
            remote_name: "yt-dlp_macos",
            sha256: "0f192b7ec147ab6288885d6351d9ab67367640029b4377576ef46dd79cf7b202",
        },
        _ => anyhow::bail!("managed yt-dlp is unsupported on {os}/{arch}"),
    };
    Ok(asset)
}

pub fn expected_sha256() -> Result<&'static str> {
    Ok(platform_asset()?.sha256())
}

pub fn download_url() -> Result<String> {
    Ok(format!(
        "https://github.com/yt-dlp/yt-dlp/releases/download/{YT_DLP_VERSION}/{}",
        platform_asset()?.remote_name(),
    ))
}

pub fn managed_path(home: &Path) -> PathBuf {
    home.join("bin").join(asset_name())
}

/// The executable is considered usable only after its bounded file digest and
/// self-reported version both match the exact pinned release. The direct path
/// command is deliberate: the generic probe invokes `cmd /C` on Windows.
pub async fn check_installed(home: &Path) -> Option<String> {
    check_installed_with_probe(
        home,
        |binary| async move { direct_version_probe(&binary).await },
    )
    .await
}

async fn check_installed_with_probe<F, Fut>(home: &Path, probe: F) -> Option<String>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    let binary = managed_path(home);
    if !binary.is_file() || !managed_binary_digest_matches(&binary) {
        return None;
    }
    let version = probe(binary).await?;
    (version.trim() == YT_DLP_VERSION).then_some(version)
}

fn managed_binary_digest_matches(binary: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(binary) else {
        return false;
    };
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let Ok(read) = file.read(&mut buffer) else {
            return false;
        };
        if read == 0 {
            break;
        }
        total = match total.checked_add(read) {
            Some(total) if total <= MAX_INSTALL_BYTES => total,
            _ => return false,
        };
        digest.update(&buffer[..read]);
    }
    expected_sha256().is_ok_and(|expected| format!("{:x}", digest.finalize()) == expected)
}

async fn direct_version_probe(binary: &Path) -> Option<String> {
    let mut command = Command::new(binary);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = command.spawn().ok()?;
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .ok()?.ok()?;
    if !output.status.success() || output.stdout.len() > 1024 {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .filter(|version| !version.trim().is_empty())
}

/// Download the named release, verify its GitHub-release SHA-256, and atomically
/// place it under the instance-owned `bin/` directory. The caller owns the
/// wizard consent/UI boundary; this primitive does no implicit prompting.
pub async fn install_pinned(home: &Path) -> Result<PathBuf> {
    let platform = platform_asset()?;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?
        .get(download_url()?)
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_INSTALL_BYTES as u64)
    {
        anyhow::bail!("yt-dlp release exceeds bounded installer size");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        append_install_chunk(&mut bytes, &chunk?)?;
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    anyhow::ensure!(
        actual == platform.sha256(),
        "yt-dlp release SHA-256 mismatch"
    );
    let path = managed_path(home);
    let parent = path.parent().context("managed yt-dlp path has no parent")?;
    std::fs::create_dir_all(parent)?;
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("install verified yt-dlp to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    let found = check_installed(home)
        .await
        .context("probe installed yt-dlp")?;
    anyhow::ensure!(
        found == YT_DLP_VERSION,
        "installed yt-dlp did not report pinned version"
    );
    Ok(path)
}

fn append_install_chunk(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let next_len = bytes
        .len()
        .checked_add(chunk.len())
        .context("yt-dlp installer length overflow")?;
    anyhow::ensure!(
        next_len <= MAX_INSTALL_BYTES,
        "yt-dlp release exceeds bounded installer size"
    );
    bytes.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_release_identity_is_exact_and_https() {
        assert_eq!(YT_DLP_VERSION, "2026.08.19");
        assert!(
            download_url()
                .unwrap()
                .starts_with("https://github.com/yt-dlp/yt-dlp/releases/download/2026.08.19/")
        );
        assert_eq!(expected_sha256().unwrap().len(), 64);
        assert!(
            expected_sha256()
                .unwrap()
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
    }
    #[test]
    fn managed_path_is_instance_owned() {
        assert!(managed_path(Path::new("home")).starts_with("home"));
        assert!(managed_path(Path::new("home")).ends_with(asset_name()));
    }

    #[test]
    fn platform_assets_are_standalone_and_unsupported_targets_fail_closed() {
        assert_eq!(
            platform_asset_for("linux", "x86_64").unwrap().remote_name(),
            "yt-dlp_linux"
        );
        assert_eq!(
            platform_asset_for("linux", "aarch64")
                .unwrap()
                .remote_name(),
            "yt-dlp_linux_aarch64"
        );
        assert_eq!(
            platform_asset_for("macos", "aarch64")
                .unwrap()
                .remote_name(),
            "yt-dlp_macos"
        );
        assert_eq!(
            platform_asset_for("windows", "x86_64")
                .unwrap()
                .remote_name(),
            "yt-dlp.exe"
        );
        assert_eq!(
            platform_asset_for("windows", "aarch64")
                .unwrap()
                .remote_name(),
            "yt-dlp_arm64.exe"
        );
        assert!(platform_asset_for("linux", "arm").is_err());
    }

    #[tokio::test]
    async fn wrong_digest_binary_is_rejected_before_any_probe() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp = tempfile::tempdir().unwrap();
        let binary = managed_path(temp.path());
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"not the pinned yt-dlp binary").unwrap();
        let called = AtomicBool::new(false);
        let called_by_probe = &called;
        let result = check_installed_with_probe(temp.path(), |_| async move {
            called_by_probe.store(true, Ordering::SeqCst);
            Some(YT_DLP_VERSION.to_string())
        })
        .await;
        assert!(result.is_none());
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn streamed_installer_accumulator_refuses_overflow_before_append() {
        let mut bytes = vec![0; MAX_INSTALL_BYTES];
        assert!(append_install_chunk(&mut bytes, &[1]).is_err());
        assert_eq!(bytes.len(), MAX_INSTALL_BYTES);
    }
}
