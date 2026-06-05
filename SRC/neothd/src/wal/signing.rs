//! KF-03 — operator proof-bundle signing key (ed25519).
//!
//! `neoth wal export --sign` signs a `.neoth-proof` tamper-evidence bundle so
//! a third party can attribute it to THIS operator. The signing key is the
//! operator's OWN per-proof key — a **separate trust root** from the project
//! release key that `updater::sig_verify` (minisign-verify) checks; the two
//! must never be conflated.
//!
//! ## DAU-safe by construction
//!
//! The signing key is auto-generated + persisted on first `--sign` use,
//! mirroring the WAL HMAC key (`wal::compaction::load_or_init_key`) EXACTLY —
//! same `getrandom` entropy, same fail-closed-on-no-RNG contract, same
//! `write_key_securely` (unix mode 0600 / Windows DPAPI-wrap + DACL) + same
//! `maybe_unwrap_dpapi` on read. The operator types nothing, sees no password
//! prompt, installs no tool. This was the unanimous verdict of the Session-34
//! 3-lens DAU-safety gremium (vs. shelling out to the `minisign` binary, which
//! is DAU-hostile + not CI-testable).
//!
//! The scheme is a raw ed25519 detached signature over
//! [`crate::wal::proof_bundle::ProofBundle::canonical_bytes`]; verification is
//! `neoth wal verify-proof` (pure-Rust, no external tool). ed25519 hashes the
//! message internally with SHA-512, so no extra digest dep is needed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Stable algorithm tag stored in the signed envelope so a future scheme
/// change is unambiguous to a verifier.
pub const SIG_ALGORITHM: &str = "ed25519-raw";

/// Default signing-key path: `~/.neoth/wal/signing.key` (the 32-byte ed25519
/// seed). Sits next to the WAL HMAC key under the same protected dir.
pub fn default_signing_key_path() -> PathBuf {
    crate::config::FreedomConfig::default_wal_dir().join("signing.key")
}

/// Load the operator's ed25519 signing key, generating + persisting a fresh
/// one on first use. DAU-safe: zero interaction. Mirrors
/// [`crate::wal::compaction::load_or_init_key`] — fail-closed if the OS RNG is
/// unavailable (a weak signing key would make the proof signature worthless).
/// The on-disk form is the raw 32-byte seed (the public key is always derived
/// from it), DPAPI-wrapped on Windows via the shared secure-write path.
pub fn load_or_init_signing_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let body =
            std::fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
        let seed = crate::wal::compaction::maybe_unwrap_dpapi(&body, path)?;
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "signing key at {} is not 32 bytes ({} given) — refusing to use a malformed key",
                path.display(),
                seed.len(),
            )
        })?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create signing key parent {}", parent.display()))?;
    }
    // 32-byte ed25519 seed via the OS CSPRNG. **Fail closed** when the OS RNG
    // is unavailable — a predictable signing key undermines the whole
    // attribution story (same contract as the HMAC key).
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .context("OS RNG unavailable — refusing to generate weak signing key")?;
    crate::wal::compaction::write_key_securely(path, &seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Base64 (standard) of the 32-byte ed25519 public key — what lands in the
/// envelope's `signer_pubkey` and what the operator shares with auditors.
pub fn pubkey_b64(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
}

/// LOAD-ONLY trusted public key: read the operator's signing key if it already
/// exists and return its base64 public key, WITHOUT generating one. Used by
/// `neoth verify` to authenticate redaction/rotation frames against the
/// operator's OWN key — it must never mint a key as a side effect of verifying,
/// and `None` (no key on disk) correctly means "no signed authorisation can be
/// trusted" so the verifier fails closed. Returns `None` on a missing/unreadable
/// /malformed key rather than erroring — a bad trust root simply trusts nothing.
pub fn load_signing_pubkey_if_present(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let body = std::fs::read(path).ok()?;
    let seed = crate::wal::compaction::maybe_unwrap_dpapi(&body, path).ok()?;
    let seed: [u8; 32] = seed.as_slice().try_into().ok()?;
    Some(pubkey_b64(&SigningKey::from_bytes(&seed)))
}

/// Sign `msg`, returning base64 (standard) of the 64-byte detached signature.
pub fn sign_b64(key: &SigningKey, msg: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.sign(msg).to_bytes())
}

/// Verify a base64 signature + base64 public key over `msg`. `Ok(())` iff the
/// signature is valid for that key over those exact bytes; a descriptive error
/// otherwise (malformed base64 / wrong key length / signature mismatch).
pub fn verify_b64(pubkey_b64: &str, sig_b64: &str, msg: &[u8]) -> Result<()> {
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64.trim())
        .context("decode signer public key base64")?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer public key is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).context("invalid ed25519 public key")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .context("decode signature base64")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig)
        .context("ed25519 signature does not match the claimed public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"the proof bundle canonical bytes";
        let sig = sign_b64(&key, msg);
        let pk = pubkey_b64(&key);
        assert!(
            verify_b64(&pk, &sig, msg).is_ok(),
            "a freshly-signed message must verify against its own key",
        );
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let sig = sign_b64(&key, b"original bytes");
        let pk = pubkey_b64(&key);
        assert!(
            verify_b64(&pk, &sig, b"tampered bytes").is_err(),
            "a different message must fail verification",
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let msg = b"bytes";
        let sig = sign_b64(&signer, msg);
        // Verify the real signature against a DIFFERENT public key → reject.
        assert!(verify_b64(&pubkey_b64(&other), &sig, msg).is_err());
    }

    #[test]
    fn verify_rejects_malformed_base64() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let pk = pubkey_b64(&key);
        assert!(verify_b64(&pk, "!!!not base64!!!", b"x").is_err());
        assert!(verify_b64("!!!not base64!!!", &sign_b64(&key, b"x"), b"x").is_err());
        // Valid base64 but wrong length (16 bytes, not 32) → reject, no panic.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(verify_b64(&short, &sign_b64(&key, b"x"), b"x").is_err());
    }

    #[test]
    fn load_or_init_generates_then_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal").join("signing.key");
        assert!(!path.exists());
        let k1 = load_or_init_signing_key(&path).expect("first load generates");
        assert!(path.exists(), "key file is persisted on first use");
        let k2 = load_or_init_signing_key(&path).expect("second load reads existing");
        // Same key both times (the public key is deterministic from the seed).
        assert_eq!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "second load must return the SAME key, not regenerate",
        );
        // A signature from the reloaded key verifies against the first key's pub.
        let msg = b"persisted-key bytes";
        assert!(verify_b64(&pubkey_b64(&k1), &sign_b64(&k2, msg), msg).is_ok());
    }

    #[test]
    fn load_rejects_malformed_seed_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        // 16 bytes (not 32) on disk → load must refuse, not silently truncate.
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert!(load_or_init_signing_key(&path).is_err());
    }
}
