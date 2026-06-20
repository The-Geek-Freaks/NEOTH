//! Shared Chrome credential-import primitives (GOLD-ARCH-08, origin C-13/D-14).
//!
//! The three platform modules (`chrome_linux`, `chrome_macos`, `chrome_windows`)
//! each carried byte-identical copies of the row/credential structs and the
//! `saltysalt`-derived AES envelope constants. They live here once; the platform
//! files re-export them and supply only the per-platform pinches: the PBKDF2
//! iteration count (Linux 1, macOS 1003) and the keyring/keychain/DPAPI source.
//! Windows decrypts the v10/v11 envelope with AES-256-GCM + a DPAPI-unwrapped
//! key, so it shares the structs (and the `v10`/`v11` prefixes) but not the
//! `saltysalt`/CBC-IV constants.

/// First 3 bytes of the modern Chrome password envelope (`v10`).
pub const V10_PREFIX: &[u8] = b"v10";

/// First 3 bytes of the `v11` password envelope. Same body shape — kept for
/// forward compatibility with Chromium-derived browsers that bumped the prefix.
pub const V11_PREFIX: &[u8] = b"v11";

/// PBKDF2 salt Chrome hardcodes on every platform that uses the
/// `saltysalt`-derived AES key (Linux + macOS). Bytes — not chars — because the
/// PBKDF2 input is byte-typed.
pub const SALTYSALT: &[u8] = b"saltysalt";

/// AES-CBC IV Chrome hardcodes on Linux + macOS. 16 ASCII space bytes.
pub const CHROME_CBC_IV: &[u8; 16] = b"                ";

/// Derived key length. AES-128 needs 16 bytes; do **NOT** change.
pub const AES_KEY_BYTES: usize = 16;

/// One row from Chrome's `logins` table — the raw shape before decrypt.
/// Shared across all three platform paths so the importer wiring stays
/// consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeLoginRow {
    pub origin_url: String,
    pub username: String,
    pub password_blob: Vec<u8>,
}

/// One decrypted Chrome credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedChromeCredential {
    pub origin_url: String,
    pub username: String,
    pub password: String,
}

impl Drop for DecryptedChromeCredential {
    fn drop(&mut self) {
        // Scrub the decrypted plaintext on drop (GOLD-SEC-12 / A-32). These
        // credentials live in a `Vec` until they are mapped into `SecretBytes`,
        // so without this the operator's Chrome passwords would linger
        // unscrubbed on the heap (and could be swapped to disk). GOLD-SEC-12 —
        // the username is sensitive too (it pairs with the password); zeroize
        // it as well.
        use zeroize::Zeroize;
        self.password.zeroize();
        self.username.zeroize();
    }
}

/// PBKDF2-HMAC-SHA1 key derivation for the `saltysalt` AES envelope, shared by
/// the Linux (iter=1) and macOS (iter=1003) Chrome paths (GOLD-ARCH-08). The
/// iteration count is the *only* per-platform pinch — Chrome fixes the salt
/// (`saltysalt`), the hash (HMAC-SHA1), and the key length (16 / AES-128) on
/// every platform that uses this envelope. Pure helper: no IO, testable in
/// isolation. The platform modules wrap this with their own `PBKDF2_ITERATIONS`
/// so their public `derive_chrome_aes_key(password)` surface (and its
/// known-answer tests) stay byte-for-byte unchanged.
pub fn derive_saltysalt_key(password: &[u8], iterations: u32) -> [u8; AES_KEY_BYTES] {
    let mut key = [0u8; AES_KEY_BYTES];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, SALTYSALT, iterations, &mut key);
    key
}

/// Error from the shared Chrome `v10`/`v11` AES-128-CBC decrypt loop. The
/// platform modules map this onto their own per-OS error enum so operator-facing
/// wizard diagnostics stay platform-specific (GOLD-ARCH-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChromeCbcError {
    /// Blob lacked a recognised `v10`/`v11` prefix.
    UnrecognizedBlob,
    /// AES-128-CBC decrypt failed (wrong key or corrupt ciphertext).
    AesCbcDecrypt,
}

/// AES-128-CBC decrypt of a Chrome `v10`/`v11` password envelope, shared by the
/// Linux + macOS paths (GOLD-ARCH-08). Strips the 3-byte prefix, decrypts with
/// the hardcoded `saltysalt` IV + PKCS#7 padding, and scrubs the in-place buffer
/// (GOLD-SEC-12 / A-32) before returning the plaintext bytes. Windows does NOT
/// use this — it decrypts the v10/v11 envelope with AES-256-GCM + a DPAPI key.
pub fn decrypt_chrome_cbc_envelope(
    aes_key: &[u8; AES_KEY_BYTES],
    blob: &[u8],
) -> Result<Vec<u8>, ChromeCbcError> {
    use aes::Aes128;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use zeroize::Zeroize;
    type Aes128CbcDec = cbc::Decryptor<Aes128>;

    if !(blob.starts_with(V10_PREFIX) || blob.starts_with(V11_PREFIX)) {
        return Err(ChromeCbcError::UnrecognizedBlob);
    }
    let ciphertext = &blob[3..];
    let mut buf = ciphertext.to_vec();
    let pt = Aes128CbcDec::new(aes_key.into(), CHROME_CBC_IV.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| ChromeCbcError::AesCbcDecrypt)?;
    let out = pt.to_vec();
    buf.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_envelope_rejects_unprefixed_blob() {
        let key = [0x42u8; AES_KEY_BYTES];
        let err = decrypt_chrome_cbc_envelope(&key, b"no-prefix-here").unwrap_err();
        assert_eq!(err, ChromeCbcError::UnrecognizedBlob);
    }

    #[test]
    fn cbc_envelope_round_trips_v10_and_v11() {
        use aes::Aes128;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<Aes128>;

        let key = [0x24u8; AES_KEY_BYTES];
        for prefix in [V10_PREFIX, V11_PREFIX] {
            let plaintext = b"shared-cbc-secret";
            let mut buf = vec![0u8; plaintext.len() + 16];
            buf[..plaintext.len()].copy_from_slice(plaintext);
            let ct = Aes128CbcEnc::new((&key).into(), CHROME_CBC_IV.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                .expect("encrypt");
            let mut blob = prefix.to_vec();
            blob.extend_from_slice(ct);
            let got = decrypt_chrome_cbc_envelope(&key, &blob).expect("decrypt");
            assert_eq!(got, plaintext, "shared CBC round-trip must recover plaintext");
        }
    }

    #[test]
    fn cbc_envelope_wrong_key_fails_cleanly() {
        // A v10 blob decrypted with the wrong key fails the PKCS#7 unpad rather
        // than panicking — the operator wizard surfaces a per-source warning.
        let mut blob = V10_PREFIX.to_vec();
        blob.extend_from_slice(&[0u8; 32]); // 2 AES blocks of zero ciphertext
        let err = decrypt_chrome_cbc_envelope(&[0x01u8; AES_KEY_BYTES], &blob).unwrap_err();
        assert_eq!(err, ChromeCbcError::AesCbcDecrypt);
    }

    #[test]
    fn derive_saltysalt_key_matches_known_iter_1() {
        // PBKDF2-HMAC-SHA1("peanuts","saltysalt",iter=1,16) = fd621fe5… (Linux KAT).
        let got = derive_saltysalt_key(b"peanuts", 1);
        let expected: [u8; 16] = [
            0xfd, 0x62, 0x1f, 0xe5, 0xa2, 0xb4, 0x02, 0x53, 0x9d, 0xfa, 0x14, 0x7c, 0xa9, 0x27,
            0x27, 0x78,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn derive_saltysalt_key_iter_count_changes_key() {
        // Linux (1) and macOS (1003) MUST diverge — drift guard.
        assert_ne!(derive_saltysalt_key(b"peanuts", 1), derive_saltysalt_key(b"peanuts", 1003));
    }
}
