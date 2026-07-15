use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use zeroize::Zeroizing;

// Reuse the updater's canonical minisign-compatible implementation. This
// signer remains a separate, narrowly scoped executable and never links or
// executes the product artifact whose bytes it signs.
#[allow(dead_code)]
#[path = "../../../../SRC/neothd/src/updater/sig_keygen.rs"]
mod sig_keygen;

const SECRET_ENV: &str = "NEOTH_RELEASE_MINISIGN_SECRET";
const PUBKEY_ENV: &str = "NEOTH_RELEASE_MINISIGN_PUBKEY";

fn signature_path(asset: &Path) -> PathBuf {
    let mut path = OsString::from(asset.as_os_str());
    path.push(".minisig");
    PathBuf::from(path)
}

fn sign_one(
    keypair: &sig_keygen::ReleaseKeypair,
    public_key: &minisign_verify::PublicKey,
    asset: &Path,
) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(asset)
        .with_context(|| format!("inspect release asset {}", asset.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "release asset must be a regular, non-symlink file: {}",
            asset.display()
        );
    }
    let filename = asset
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .with_context(|| format!("release asset name is not valid UTF-8: {}", asset.display()))?;
    let payload =
        std::fs::read(asset).with_context(|| format!("read release asset {}", asset.display()))?;
    let trusted_comment = format!("file:{filename}");
    let signature = keypair.sign_minisig(&payload, "neoth release", &trusted_comment);

    let decoded = minisign_verify::Signature::decode(&signature)
        .map_err(|error| anyhow::anyhow!("decode generated signature for {filename}: {error}"))?;
    public_key
        .verify(&payload, &decoded, false)
        .map_err(|error| anyhow::anyhow!("verify generated signature for {filename}: {error}"))?;
    let expected_line = format!("trusted comment: {trusted_comment}");
    if signature
        .lines()
        .filter(|line| line.starts_with("trusted comment:"))
        .count()
        != 1
        || !signature.lines().any(|line| line == expected_line)
    {
        bail!("generated signature is not bound to {trusted_comment}");
    }

    let output = signature_path(asset);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .with_context(|| format!("create signature {}", output.display()))?;
    file.write_all(signature.as_bytes())
        .with_context(|| format!("write signature {}", output.display()))?;
    file.sync_all()
        .with_context(|| format!("flush signature {}", output.display()))?;
    Ok(output)
}

fn run() -> Result<()> {
    let assets: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if assets.is_empty() {
        bail!("usage: neoth-release-signer ASSET [ASSET ...]");
    }

    let expected_pubkey =
        std::env::var(PUBKEY_ENV).with_context(|| format!("{PUBKEY_ENV} is required"))?;
    let expected_pubkey = expected_pubkey.trim();
    if expected_pubkey.is_empty() {
        bail!("{PUBKEY_ENV} is empty");
    }
    let public_key = minisign_verify::PublicKey::from_base64(expected_pubkey)
        .map_err(|error| anyhow::anyhow!("release minisign public key is malformed: {error}"))?;

    let secret = Zeroizing::new(
        std::env::var(SECRET_ENV).with_context(|| format!("{SECRET_ENV} is required"))?,
    );
    let secret = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(secret.trim())
            .with_context(|| format!("{SECRET_ENV} is not valid base64"))?,
    );
    let keypair = sig_keygen::ReleaseKeypair::from_secret_bytes(&secret)
        .with_context(|| format!("{SECRET_ENV} is not a valid release secret"))?;
    if keypair.public_key_base64() != expected_pubkey {
        bail!("release minisign secret does not match the pinned public key");
    }

    for asset in assets {
        let output = sign_one(&keypair, &public_key, &asset)?;
        println!("signed {}", output.display());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("release signing failed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_exact_file_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let asset = dir.path().join("neoth-v1.0.0.tar.gz");
        std::fs::write(&asset, b"release bytes").unwrap();
        let keypair = sig_keygen::ReleaseKeypair::generate().unwrap();
        let public_key =
            minisign_verify::PublicKey::from_base64(&keypair.public_key_base64()).unwrap();

        let output = sign_one(&keypair, &public_key, &asset).unwrap();
        let signature = std::fs::read_to_string(output).unwrap();
        assert!(signature.contains("trusted comment: file:neoth-v1.0.0.tar.gz\n"));
        assert!(sign_one(&keypair, &public_key, &asset).is_err());
    }
}
