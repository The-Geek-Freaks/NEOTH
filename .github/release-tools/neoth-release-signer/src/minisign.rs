//! Minimal minisign-compatible signing primitive for the isolated release signer.
//!
//! Keep this implementation local to the signer crate. The resulting binary is
//! executed with the release signing secret and therefore must never compile or
//! include source from the NEOTH product tree.

use anyhow::Result;
use base64::Engine as _;
use blake2::{Blake2b512, Digest as _};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroize as _;

const KEY_ALG: &[u8; 2] = b"Ed";
const SIG_ALG_PREHASHED: &[u8; 2] = b"ED";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Signing key reconstructed from NEOTH's compact `key_id || seed` secret.
pub(crate) struct ReleaseKeypair {
    key_id: [u8; 8],
    signing_key: SigningKey,
}

impl ReleaseKeypair {
    pub(crate) fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 40 {
            anyhow::bail!("release secret key must be 40 bytes, got {}", bytes.len());
        }

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[..8]);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[8..]);

        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();

        Ok(Self {
            key_id,
            signing_key,
        })
    }

    /// Base64 of `"Ed" || key_id || ed25519_public_key`, as expected by
    /// `minisign_verify::PublicKey::from_base64` in the product verifier.
    pub(crate) fn public_key_base64(&self) -> String {
        let mut blob = Vec::with_capacity(42);
        blob.extend_from_slice(KEY_ALG);
        blob.extend_from_slice(&self.key_id);
        blob.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        b64().encode(blob)
    }

    /// Produce the modern prehashed minisign format accepted with
    /// `allow_legacy = false` by the product verifier.
    pub(crate) fn sign_minisig(
        &self,
        data: &[u8],
        untrusted_comment: &str,
        trusted_comment: &str,
    ) -> String {
        let prehash = Blake2b512::digest(data);
        let signature = self.signing_key.sign(prehash.as_ref());
        let signature_bytes = signature.to_bytes();

        let mut signature_blob = Vec::with_capacity(74);
        signature_blob.extend_from_slice(SIG_ALG_PREHASHED);
        signature_blob.extend_from_slice(&self.key_id);
        signature_blob.extend_from_slice(&signature_bytes);

        let mut global_input = Vec::with_capacity(signature_bytes.len() + trusted_comment.len());
        global_input.extend_from_slice(&signature_bytes);
        global_input.extend_from_slice(trusted_comment.as_bytes());
        let global_signature = self.signing_key.sign(&global_input);

        format!(
            "untrusted comment: {untrusted_comment}\n{}\ntrusted comment: {trusted_comment}\n{}\n",
            b64().encode(signature_blob),
            b64().encode(global_signature.to_bytes()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_SECRET_B64: &str = "TkVPVEhWMTAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==";
    const VECTOR_PUBLIC_KEY_B64: &str = "RWRORU9USFYxMAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const VECTOR_PAYLOAD: &[u8] = b"NEOTH release signer compatibility vector v1\n";
    const VECTOR_TRUSTED_COMMENT: &str = "file:neoth-v1.0.0-test.tar.gz";
    const VECTOR_SIGNATURE: &str = concat!(
        "untrusted comment: neoth release\n",
        "RURORU9USFYxMHDdZ44VAzByH/UxXcyEgz9mubfDRpTikj+C75w/RCNGFJnC7jPcsVGls62ygMrBzxDJZ0samN+kqUjLY1Eo3Qk=\n",
        "trusted comment: file:neoth-v1.0.0-test.tar.gz\n",
        "lrPfL+p+MRh5q77sIstBvI4qdLyOKHpWeAZ+4EBh8c4viZhYcGWHDeSA4WezdY9nU0vRuZkwojWFKBPXO+bxBQ==\n",
    );

    fn vector_keypair() -> ReleaseKeypair {
        let secret = b64().decode(VECTOR_SECRET_B64).unwrap();
        ReleaseKeypair::from_secret_bytes(&secret).unwrap()
    }

    #[test]
    fn known_vector_matches_the_product_verifier_contract() {
        let keypair = vector_keypair();
        assert_eq!(keypair.public_key_base64(), VECTOR_PUBLIC_KEY_B64);

        let signature =
            keypair.sign_minisig(VECTOR_PAYLOAD, "neoth release", VECTOR_TRUSTED_COMMENT);
        assert_eq!(signature, VECTOR_SIGNATURE);

        // This is the exact minisign-verify API and non-legacy mode used by
        // `SRC/neothd/src/updater/sig_verify.rs`. The isolation contract also
        // pins this crate to the same locked verifier version as the product.
        let public_key = minisign_verify::PublicKey::from_base64(VECTOR_PUBLIC_KEY_B64).unwrap();
        let decoded = minisign_verify::Signature::decode(VECTOR_SIGNATURE).unwrap();
        public_key.verify(VECTOR_PAYLOAD, &decoded, false).unwrap();
        assert_eq!(decoded.trusted_comment(), VECTOR_TRUSTED_COMMENT);
    }

    #[test]
    fn known_vector_rejects_tampered_payload() {
        let public_key = minisign_verify::PublicKey::from_base64(VECTOR_PUBLIC_KEY_B64).unwrap();
        let decoded = minisign_verify::Signature::decode(VECTOR_SIGNATURE).unwrap();
        assert!(
            public_key
                .verify(
                    b"NEOTH release signer compatibility vector v2\n",
                    &decoded,
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn malformed_secret_lengths_are_rejected() {
        assert!(ReleaseKeypair::from_secret_bytes(&[0u8; 39]).is_err());
        assert!(ReleaseKeypair::from_secret_bytes(&[0u8; 41]).is_err());
    }
}
