//! C-03b Linux — Chrome `Login Data` decrypt via Secret Service (DBus)
//! + AES-128-CBC with `saltysalt`-derived key.
//!
//! Chrome on Linux stores each password as a `v10`/`v11`-prefixed
//! AES-128-CBC ciphertext. The symmetric key is derived via PBKDF2-
//! HMAC-SHA1 (iter=1, salt=`"saltysalt"`, dklen=16) from a password
//! stored in the operator's login keyring (GNOME Keyring or KWallet
//! accessed via the freedesktop Secret Service DBus API). When the
//! keyring is unavailable, Chrome falls back to a hardcoded
//! `"peanuts"` password — we honour that fallback so importers on
//! headless CI runners (no DBus session) still surface readable
//! passwords from profiles that were created without a keyring.
//!
//! ## Envelope shape
//!
//! ```text
//! [0..3]   "v10"  or  "v11"        (3-byte prefix)
//! [3..]    AES-128-CBC ciphertext  (PKCS#7-padded)
//! ```
//!
//! The IV is **NOT** in the blob — Chrome hardcodes it to 16 ASCII
//! spaces (`b"                "`). Deviating from this matches no
//! known Chrome version, so we pin the constant here + in tests.
//!
//! Non-prefixed blobs are not handled; they would predate the v10
//! migration (Chromium ~46, 2015) and modern installs have all
//! migrated. The importer skips with a per-entry warning rather
//! than guessing.
//!
//! ## Side-channel hygiene
//!
//! - **Single Err variant for crypto fail** — `AesCbcDecrypt` collapses
//!   wrong-key / wrong-pad / corrupt-ciphertext into one shape so the
//!   audit chain can't tell which branch fired (matches C-04b policy +
//!   the C-03b Windows half).
//! - **Keyring prompts pass through** — when the operator's login
//!   keyring is locked, `Collection::ensure_unlocked` may surface a
//!   graphical password prompt. We do not try to suppress this; it is
//!   the freedesktop security model + matches Chrome's own behaviour.

use std::collections::HashMap;
use std::path::Path;

use aes::Aes128;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha1::Sha1;

type Aes128CbcDec = cbc::Decryptor<Aes128>;

// GOLD-ARCH-08 — the row/credential structs + the saltysalt/CBC envelope
// constants are shared in `chrome_common`; Linux supplies only the PBKDF2
// iteration count (1) + the Secret Service keyring source.
pub use crate::credentials::chrome_common::{
    AES_KEY_BYTES, CHROME_CBC_IV, ChromeLoginRow, DecryptedChromeCredential, SALTYSALT, V10_PREFIX,
    V11_PREFIX,
};

/// Fallback PBKDF2 password Chrome uses on Linux when the operator's
/// login keyring is unavailable (no DBus, declined keyring unlock,
/// or no installed Secret Service backend). Matches Chromium's
/// `key_storage_linux.cc::kDefaultPassword`.
pub const CHROME_FALLBACK_PASSWORD: &[u8] = b"peanuts";

/// PBKDF2 iteration count. Linux installs use 1; do **NOT** change —
/// would break interop with every existing Chrome profile.
pub const PBKDF2_ITERATIONS: u32 = 1;

/// Errors surfaced by the Linux Chrome decrypt path. Importer
/// collapses variants into a generic per-source diagnostic before
/// the audit chain — variant differentiation for operator-facing
/// wizard warnings + drift-guard tests only.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ChromeLinuxError {
    #[error("Secret Service (DBus) connection failed: {0}")]
    SecretServiceConnect(String),
    #[error("Secret Service collection unlock failed: {0}")]
    KeyringUnlock(String),
    #[error("Secret Service item lookup failed: {0}")]
    KeyringLookup(String),
    #[error("Secret Service item secret read failed: {0}")]
    KeyringSecretRead(String),
    #[error("AES-128-CBC decrypt failed (wrong key or corrupt ciphertext)")]
    AesCbcDecrypt,
    #[error("password envelope unsupported format (no v10/v11 prefix)")]
    UnrecognizedBlob,
    #[error("SQLite read of Login Data failed: {0}")]
    Sqlite(String),
}

/// PBKDF2-HMAC-SHA1 with Chrome's hardcoded `"saltysalt"` salt + 1
/// iteration → 16-byte AES-128 key. Pure helper — testable without
/// any IO. The PBKDF2 input is the keyring-supplied password (typ
/// 24 base64 bytes from libsecret) or the `"peanuts"` fallback.
pub fn derive_chrome_aes_key(password: &[u8]) -> [u8; AES_KEY_BYTES] {
    let mut key = [0u8; AES_KEY_BYTES];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, SALTYSALT, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Decrypt one password BLOB from Chrome's `password_value` column.
/// Strips the v10/v11 prefix + runs AES-128-CBC with the hardcoded
/// `"                "` IV. Non-prefixed blobs (legacy ~pre-2015
/// Chromium) surface as `UnrecognizedBlob` — caller folds into a
/// per-entry warning so a single bad row doesn't abort the import.
pub fn decrypt_chrome_password_linux(
    aes_key: &[u8; AES_KEY_BYTES],
    blob: &[u8],
) -> Result<Vec<u8>, ChromeLinuxError> {
    if !(blob.starts_with(V10_PREFIX) || blob.starts_with(V11_PREFIX)) {
        return Err(ChromeLinuxError::UnrecognizedBlob);
    }
    let ciphertext = &blob[3..];
    let mut buf = ciphertext.to_vec();
    let pt = Aes128CbcDec::new(aes_key.into(), CHROME_CBC_IV.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| ChromeLinuxError::AesCbcDecrypt)?;
    let out = pt.to_vec();
    // Scrub the in-place decrypted buffer (GOLD-SEC-12 / A-32).
    use zeroize::Zeroize;
    buf.zeroize();
    Ok(out)
}

/// Look up Chrome's symmetric password in the operator's freedesktop
/// Secret Service (login keyring). Falls back to the hardcoded
/// `"peanuts"` password when:
///   - the DBus session is unavailable (headless CI / no display),
///   - the default collection refuses to unlock,
///   - no item matches the `application=chrome`/`chromium`/`brave`
///     schema (operator never opened Chrome with keyring support).
///
/// Returns the bytes ready to feed into [`derive_chrome_aes_key`].
pub async fn get_chrome_password_from_keyring() -> Vec<u8> {
    match get_chrome_password_strict().await {
        Ok(pw) => pw,
        Err(_) => CHROME_FALLBACK_PASSWORD.to_vec(),
    }
}

/// Strict variant of [`get_chrome_password_from_keyring`] that
/// surfaces every Secret Service failure mode as `Err` instead of
/// silently falling back. Useful for tests + diagnostic CLI paths
/// where the operator wants to know why their keyring was bypassed.
pub async fn get_chrome_password_strict() -> Result<Vec<u8>, ChromeLinuxError> {
    use secret_service::{EncryptionType, SecretService};

    let ss = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| ChromeLinuxError::SecretServiceConnect(e.to_string()))?;
    let collection = ss
        .get_default_collection()
        .await
        .map_err(|e| ChromeLinuxError::KeyringLookup(e.to_string()))?;
    collection
        .ensure_unlocked()
        .await
        .map_err(|e| ChromeLinuxError::KeyringUnlock(e.to_string()))?;

    // Try Chromium-family browser schemas in order. Chromium-derived
    // browsers (Brave, Edge-on-Linux, Vivaldi) reuse the same schema
    // attribute scheme; we accept any match.
    for application in ["chrome", "chromium", "brave"] {
        let mut attrs = HashMap::new();
        attrs.insert("application", application);
        let items = ss
            .search_items(attrs)
            .await
            .map_err(|e| ChromeLinuxError::KeyringLookup(e.to_string()))?;
        // search_items returns both unlocked + locked matches. The
        // unlocked Vec is the one we can read without further unlock
        // prompts — prefer it.
        if let Some(item) = items.unlocked.first() {
            let secret = item
                .get_secret()
                .await
                .map_err(|e| ChromeLinuxError::KeyringSecretRead(e.to_string()))?;
            return Ok(secret);
        }
        if let Some(item) = items.locked.first() {
            item.unlock()
                .await
                .map_err(|e| ChromeLinuxError::KeyringUnlock(e.to_string()))?;
            let secret = item
                .get_secret()
                .await
                .map_err(|e| ChromeLinuxError::KeyringSecretRead(e.to_string()))?;
            return Ok(secret);
        }
    }
    Err(ChromeLinuxError::KeyringLookup(
        "no chrome/chromium/brave item found in default collection".to_string(),
    ))
}

/// Read all rows of Chrome's `logins` table. Opens read-only so a
/// concurrent Chrome process holding a write lock doesn't block us.
pub fn read_chrome_logins(login_data_path: &Path) -> Result<Vec<ChromeLoginRow>, ChromeLinuxError> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = rusqlite::Connection::open_with_flags(login_data_path, flags)
        .map_err(|e| ChromeLinuxError::Sqlite(e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| ChromeLinuxError::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ChromeLoginRow {
                origin_url: row.get(0)?,
                username: row.get(1)?,
                password_blob: row.get(2)?,
            })
        })
        .map_err(|e| ChromeLinuxError::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| ChromeLinuxError::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

/// Full discover orchestration: pulls the keyring password (or
/// fallback), derives the AES key, opens Login Data, decrypts every
/// row. Per-entry failures fold into the `warnings` Vec; whole-flow
/// failures (SQLite open failed, etc.) surface as `Err`.
pub async fn discover_chrome_credentials_linux(
    login_data_path: &Path,
) -> Result<(Vec<DecryptedChromeCredential>, Vec<String>), ChromeLinuxError> {
    let password = get_chrome_password_from_keyring().await;
    let aes_key = derive_chrome_aes_key(&password);
    let path = login_data_path.to_path_buf();
    let rows = tokio::task::spawn_blocking(move || read_chrome_logins(&path))
        .await
        .map_err(|e| ChromeLinuxError::Sqlite(format!("blocking task join failed: {e}")))??;

    let mut creds = Vec::with_capacity(rows.len());
    let mut warnings = Vec::new();
    for row in rows {
        match decrypt_chrome_password_linux(&aes_key, &row.password_blob) {
            Ok(password_bytes) => match String::from_utf8(password_bytes) {
                Ok(password) => creds.push(DecryptedChromeCredential {
                    origin_url: row.origin_url,
                    username: row.username,
                    password,
                }),
                Err(e) => warnings.push(format!(
                    "skipped {}: password not UTF-8 ({} bytes)",
                    row.origin_url,
                    e.into_bytes().len()
                )),
            },
            Err(e) => warnings.push(format!("skipped {}: {}", row.origin_url, e)),
        }
    }
    Ok((creds, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aes_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        type Aes128CbcEnc = cbc::Encryptor<Aes128>;
        use cbc::cipher::BlockEncryptMut;
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes128CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("encrypt must succeed")
            .len();
        buf.truncate(ct_len);
        buf
    }

    fn build_v10_envelope(key: &[u8; 16], plaintext: &[u8], prefix: &[u8]) -> Vec<u8> {
        let ct = aes_encrypt(key, CHROME_CBC_IV, plaintext);
        let mut blob = Vec::with_capacity(prefix.len() + ct.len());
        blob.extend_from_slice(prefix);
        blob.extend_from_slice(&ct);
        blob
    }

    // ── PBKDF2 KDF ────────────────────────────────────────────────

    #[test]
    fn derive_chrome_aes_key_known_answer_test_peanuts() {
        // PBKDF2-HMAC-SHA1("peanuts", "saltysalt", iter=1, dklen=16).
        // This is the well-documented Chromium Linux v10 fixed key; verified
        // independently with `python -c "import hashlib;
        // print(hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1,
        // 16).hex())"` → fd621fe5a2b402539dfa147ca9272778.
        let got = derive_chrome_aes_key(CHROME_FALLBACK_PASSWORD);
        let expected: [u8; 16] = [
            0xfd, 0x62, 0x1f, 0xe5, 0xa2, 0xb4, 0x02, 0x53, 0x9d, 0xfa, 0x14, 0x7c, 0xa9, 0x27,
            0x27, 0x78,
        ];
        assert_eq!(got, expected, "Chrome PBKDF2('peanuts') KAT must match");
    }

    #[test]
    fn derive_chrome_aes_key_different_passwords_diverge() {
        let a = derive_chrome_aes_key(b"password1");
        let b = derive_chrome_aes_key(b"password2");
        assert_ne!(a, b, "different passwords must produce different keys");
    }

    #[test]
    fn derive_chrome_aes_key_empty_password_does_not_panic() {
        let got = derive_chrome_aes_key(b"");
        assert_ne!(got, [0u8; 16], "empty-pw KDF must not return all-zeros");
    }

    // ── v10/v11 envelope round-trip ───────────────────────────────

    #[test]
    fn decrypt_chrome_password_linux_v10_round_trip() {
        let key: [u8; 16] = [0x42; 16];
        let plaintext = b"super-secret-linux-pass";
        let blob = build_v10_envelope(&key, plaintext, V10_PREFIX);
        let recovered = decrypt_chrome_password_linux(&key, &blob).expect("v10 round-trip");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_linux_v11_round_trip() {
        let key: [u8; 16] = [0x55; 16];
        let plaintext = b"v11-linux-data";
        let blob = build_v10_envelope(&key, plaintext, V11_PREFIX);
        let recovered = decrypt_chrome_password_linux(&key, &blob).expect("v11 round-trip");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_linux_wrong_key_returns_err() {
        let key: [u8; 16] = [0x42; 16];
        let wrong: [u8; 16] = [0x43; 16];
        let blob = build_v10_envelope(&key, b"data", V10_PREFIX);
        // 8-perturbation defence against the rare valid-pad coincidence
        // (lifted from C-04b chunk 1 — same probability bound).
        let mut got_err = false;
        for nudge in 0..8 {
            let mut b = blob.clone();
            b[3] ^= nudge; // perturb first ciphertext byte
            if decrypt_chrome_password_linux(&wrong, &b).is_err() {
                got_err = true;
                break;
            }
        }
        assert!(got_err, "wrong key MUST surface as Err in 8 trials");
    }

    #[test]
    fn decrypt_chrome_password_linux_unrecognized_prefix_returns_err() {
        let key: [u8; 16] = [0; 16];
        // No v10/v11 prefix → unrecognized.
        let blob = vec![0x01, 0x02, 0x03, 0x04];
        let err = decrypt_chrome_password_linux(&key, &blob).unwrap_err();
        assert_eq!(err, ChromeLinuxError::UnrecognizedBlob);
    }

    #[test]
    fn decrypt_chrome_password_linux_empty_after_prefix_errs() {
        // v10 prefix but zero ciphertext bytes — AES-CBC needs ≥1
        // block (16 bytes) and PKCS#7 unpad will reject the empty.
        let key: [u8; 16] = [0; 16];
        let blob = V10_PREFIX.to_vec();
        let err = decrypt_chrome_password_linux(&key, &blob).unwrap_err();
        assert_eq!(err, ChromeLinuxError::AesCbcDecrypt);
    }

    #[test]
    fn decrypt_chrome_password_linux_with_peanuts_round_trip() {
        // Integration-style: derive the AES key from the "peanuts"
        // fallback (the path a CI runner without DBus exercises),
        // build a v10 envelope, decrypt with the same key. Pins the
        // end-to-end shape any importer running on a headless host
        // will use.
        let aes_key = derive_chrome_aes_key(CHROME_FALLBACK_PASSWORD);
        let plaintext = b"linux-no-keyring-test";
        let blob = build_v10_envelope(&aes_key, plaintext, V10_PREFIX);
        let recovered = decrypt_chrome_password_linux(&aes_key, &blob)
            .expect("peanuts-derived-key path must round-trip");
        assert_eq!(recovered, plaintext.to_vec());
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn constants_are_canonical() {
        assert_eq!(V10_PREFIX, b"v10");
        assert_eq!(V11_PREFIX, b"v11");
        assert_eq!(SALTYSALT, b"saltysalt");
        assert_eq!(CHROME_CBC_IV.as_slice(), b"                "); // exactly 16 spaces
        assert_eq!(CHROME_CBC_IV.len(), 16);
        assert_eq!(CHROME_FALLBACK_PASSWORD, b"peanuts");
        assert_eq!(PBKDF2_ITERATIONS, 1);
        assert_eq!(AES_KEY_BYTES, 16);
    }
}
