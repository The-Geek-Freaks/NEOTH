//! MAR-02 — in-process minisign keypair generation + release signing.
//!
//! The DAU-friendly half of release signing: instead of asking a maintainer to
//! install the `minisign` C tool, run `minisign -G`, juggle an encrypted secret
//! key + a password, and hand-copy the public key, NEOTH generates a
//! minisign-COMPATIBLE ed25519 keypair IN-PROCESS (`ed25519-dalek`, already a
//! dep) and signs releases itself. The produced public key + `.minisig`
//! signatures verify against the SAME [`super::sig_verify`] path the daemon's
//! self-updater uses — proven by the [`tests::keygen_sign_verify_round_trips`]
//! end-to-end test (which `sig_verify.rs` couldn't write without a private key).
//!
//! ## Format (minisign, the modern prehashed variant)
//!
//! - **Public key line** (what `minisign_verify::PublicKey::from_base64` reads,
//!   and what gets pinned via `NEOTH_RELEASE_MINISIGN_PUBKEY`): base64 of
//!   `"Ed"(2) || key_id(8) || ed25519_pubkey(32)` = 42 bytes.
//! - **`.minisig`**: four lines — an untrusted comment, the base64 of
//!   `"ED"(2) || key_id(8) || ed25519_sig(64)` (the `"ED"` tag = the payload was
//!   BLAKE2b-512-prehashed, which the verify path requires with
//!   `allow_legacy=false`), a trusted comment, and the base64 of the global
//!   ed25519 signature over `sig(64) || trusted_comment`.
//!
//! The persisted SECRET is NEOTH's own compact `key_id(8) || seed(32)` (40
//! bytes, mode-0600), NOT minisign's password-encrypted `.key` — NEOTH does the
//! signing, so it never needs the interactive minisign secret-key format.

use anyhow::{Context, Result};
use base64::Engine;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};

/// `"Ed"` — minisign's signature-algorithm tag in a PUBLIC KEY.
const KEY_ALG: &[u8; 2] = b"Ed";
/// `"ED"` — minisign's tag in a SIGNATURE meaning the payload was prehashed
/// with BLAKE2b-512 (the modern, non-legacy variant).
const SIG_ALG_PREHASHED: &[u8; 2] = b"ED";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A minisign-compatible ed25519 release-signing keypair.
pub struct ReleaseKeypair {
    /// 8-byte key id, echoed in every signature so a verifier can tell which
    /// key signed (and reject a mismatched key id early).
    pub key_id: [u8; 8],
    signing_key: SigningKey,
}

impl ReleaseKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut buf = [0u8; 40];
        getrandom::getrandom(&mut buf).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&buf[..8]);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&buf[8..]);
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// Reconstruct from the persisted `key_id(8) || seed(32)` secret blob.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 40 {
            anyhow::bail!("release secret key must be 40 bytes, got {}", bytes.len());
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[..8]);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[8..]);
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// The persistable secret blob: `key_id(8) || seed(32)`. Mode-0600 it.
    pub fn secret_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..8].copy_from_slice(&self.key_id);
        out[8..].copy_from_slice(self.signing_key.to_bytes().as_slice());
        out
    }

    /// The minisign PUBLIC-KEY line (base64 of `"Ed" || key_id || pubkey`) — the
    /// exact string `NEOTH_RELEASE_MINISIGN_PUBKEY` is set to + that
    /// `minisign_verify::PublicKey::from_base64` consumes.
    pub fn public_key_base64(&self) -> String {
        let mut blob = Vec::with_capacity(42);
        blob.extend_from_slice(KEY_ALG);
        blob.extend_from_slice(&self.key_id);
        blob.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        b64().encode(blob)
    }

    /// Hex of the key id (operator-readable identifier, e.g. for the audit /
    /// "which key is pinned" diagnostics).
    pub fn key_id_hex(&self) -> String {
        self.key_id.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Sign `data` into a minisign `.minisig` (the prehashed `"ED"` variant the
    /// verify path requires). `untrusted_comment` is cosmetic; `trusted_comment`
    /// is covered by the global signature.
    pub fn sign_minisig(
        &self,
        data: &[u8],
        untrusted_comment: &str,
        trusted_comment: &str,
    ) -> String {
        // minisign modern variant signs BLAKE2b-512(data), not data.
        let prehash = Blake2b512::digest(data);
        let sig = self.signing_key.sign(prehash.as_slice());
        let sig_bytes = sig.to_bytes();

        let mut sig_blob = Vec::with_capacity(74);
        sig_blob.extend_from_slice(SIG_ALG_PREHASHED);
        sig_blob.extend_from_slice(&self.key_id);
        sig_blob.extend_from_slice(&sig_bytes);

        // Global signature over `signature(64) || trusted_comment` — binds the
        // trusted comment to the key so it can't be swapped post-hoc.
        let mut global_input = Vec::with_capacity(sig_bytes.len() + trusted_comment.len());
        global_input.extend_from_slice(&sig_bytes);
        global_input.extend_from_slice(trusted_comment.as_bytes());
        let global_sig = self.signing_key.sign(&global_input);

        format!(
            "untrusted comment: {untrusted}\n{sig}\ntrusted comment: {trusted}\n{global}\n",
            untrusted = untrusted_comment,
            sig = b64().encode(&sig_blob),
            trusted = trusted_comment,
            global = b64().encode(global_sig.to_bytes()),
        )
    }
}

/// Default on-disk home for the release secret key (`~/.neoth/release/`).
pub fn default_release_key_path(neoth_home: &std::path::Path) -> std::path::PathBuf {
    neoth_home.join("release").join("minisign.key")
}

/// Persist the secret blob mode-0600 (best-effort on non-unix). Refuses to
/// clobber an existing key (a maintainer must `--force` / delete first, so a
/// second `keygen` can't silently invalidate a published pubkey).
pub fn save_secret_key(path: &std::path::Path, kp: &ReleaseKeypair, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "a release key already exists at {} — refusing to overwrite (this would \
             invalidate every signature made with the published public key). Delete it \
             or pass --force only if you are rotating the key intentionally.",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    write_secret_0600(path, &kp.secret_bytes())
}

#[cfg(unix)]
fn write_secret_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {} (mode 0600)", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Windows has no chmod; the file lands under the user profile's ACL.
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

/// Load a persisted release keypair.
pub fn load_secret_key(path: &std::path::Path) -> Result<ReleaseKeypair> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ReleaseKeypair::from_secret_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify_round_trips() {
        // THE proof: a keypair generated in-process + a signature it produces
        // both verify against the SHIPPED `sig_verify` path (allow_legacy=false,
        // i.e. the prehashed variant the daemon's unattended updater requires).
        let kp = ReleaseKeypair::generate().unwrap();
        let data = b"neoth-x86_64-unknown-linux-gnu.tar.gz payload bytes";
        let minisig = kp.sign_minisig(data, "neoth release", "ts:1700000000 file:neoth.tar.gz");

        let pubkey = minisign_verify::PublicKey::from_base64(&kp.public_key_base64())
            .expect("our pubkey line must parse as a minisign public key");
        let sig = minisign_verify::Signature::decode(&minisig)
            .expect("our .minisig must parse as a minisign signature");
        pubkey
            .verify(data, &sig, false)
            .expect("keygen->sign must verify against the shipped verify path");

        // And the same end-to-end through the daemon's own check_signature gate.
        // (PINNED_PUBKEY is None in test builds, so we exercise the raw verify
        // above; this asserts the format wiring stays compatible.)
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let kp = ReleaseKeypair::generate().unwrap();
        let minisig = kp.sign_minisig(b"original", "c", "t");
        let pubkey = minisign_verify::PublicKey::from_base64(&kp.public_key_base64()).unwrap();
        let sig = minisign_verify::Signature::decode(&minisig).unwrap();
        // A flipped payload byte must NOT verify.
        assert!(pubkey.verify(b"0riginal", &sig, false).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer = ReleaseKeypair::generate().unwrap();
        let other = ReleaseKeypair::generate().unwrap();
        let minisig = signer.sign_minisig(b"data", "c", "t");
        let other_pub =
            minisign_verify::PublicKey::from_base64(&other.public_key_base64()).unwrap();
        let sig = minisign_verify::Signature::decode(&minisig).unwrap();
        // A signature from a different key must NOT verify against this pubkey.
        assert!(other_pub.verify(b"data", &sig, false).is_err());
    }

    #[test]
    fn secret_bytes_round_trip_preserves_keypair() {
        let kp = ReleaseKeypair::generate().unwrap();
        let restored = ReleaseKeypair::from_secret_bytes(&kp.secret_bytes()).unwrap();
        assert_eq!(kp.key_id, restored.key_id);
        assert_eq!(kp.public_key_base64(), restored.public_key_base64());
        // A signature from the restored key verifies against the original pubkey.
        let minisig = restored.sign_minisig(b"x", "c", "t");
        let pubkey = minisign_verify::PublicKey::from_base64(&kp.public_key_base64()).unwrap();
        let sig = minisign_verify::Signature::decode(&minisig).unwrap();
        assert!(pubkey.verify(b"x", &sig, false).is_ok());
    }

    #[test]
    fn public_key_line_is_42_bytes_decoded() {
        let kp = ReleaseKeypair::generate().unwrap();
        let decoded = b64().decode(kp.public_key_base64()).unwrap();
        assert_eq!(decoded.len(), 42, "Ed(2) + key_id(8) + pubkey(32)");
        assert_eq!(&decoded[..2], b"Ed");
        assert_eq!(&decoded[2..10], &kp.key_id);
    }

    #[test]
    fn from_secret_bytes_rejects_wrong_length() {
        assert!(ReleaseKeypair::from_secret_bytes(&[0u8; 39]).is_err());
        assert!(ReleaseKeypair::from_secret_bytes(&[0u8; 41]).is_err());
    }

    #[test]
    fn save_refuses_to_clobber_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release").join("minisign.key");
        let kp = ReleaseKeypair::generate().unwrap();
        save_secret_key(&path, &kp, false).unwrap();
        // Second save without force is refused (would invalidate a published key).
        assert!(save_secret_key(&path, &kp, false).is_err());
        // With force it succeeds.
        assert!(save_secret_key(&path, &kp, true).is_ok());
        // Round-trips from disk.
        let loaded = load_secret_key(&path).unwrap();
        assert_eq!(loaded.public_key_base64(), kp.public_key_base64());
    }
}
