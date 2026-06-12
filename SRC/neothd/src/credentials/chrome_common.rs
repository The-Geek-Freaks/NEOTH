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
