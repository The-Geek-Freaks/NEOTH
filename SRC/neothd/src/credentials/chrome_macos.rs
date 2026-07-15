//! C-03b macOS — Chrome `Login Data` decrypt via Login Keychain +
//! AES-128-CBC with `saltysalt`-derived key (iter=1003).
//!
//! Chrome on macOS stores each saved password as a `v10`/`v11`-prefixed
//! AES-128-CBC ciphertext. The symmetric key is derived via PBKDF2-
//! HMAC-SHA1 (**iter=1003**, salt=`"saltysalt"`, dklen=16) from a
//! per-installation password kept in the operator's Login Keychain.
//! The keychain item is looked up by service+account:
//!
//! ```text
//! service = "Chrome Safe Storage"   (or "Chromium Safe Storage" / "Brave Safe Storage")
//! account = "Chrome"
//! ```
//!
//! **iter=1003 vs iter=1** — the macOS path uses 1003 iterations
//! (a Chrome legacy quirk); Linux uses 1. Don't unify these without
//! verifying against the actual Chromium source — the constant is
//! per-platform.
//!
//! ## Envelope shape
//!
//! ```text
//! [0..3]   "v10"  or  "v11"        (3-byte prefix)
//! [3..]    AES-128-CBC ciphertext  (PKCS#7-padded)
//! ```
//!
//! IV is hardcoded to 16 ASCII spaces (same as Linux).
//!
//! ## Keychain access prompts
//!
//! macOS surfaces an interactive password prompt the first time a
//! non-Chrome process accesses the Chrome keychain item ("neothd
//! wants to access your Login Keychain"). We don't try to bypass
//! this — it's Apple's security model and silencing it would break
//! the operator's trust assumptions about what NEOTH can read.
//!
//! ## Side-channel hygiene
//!
//! - **Single Err variant for crypto fail** — `AesCbcDecrypt` collapses
//!   wrong-key / wrong-pad / corrupt-ciphertext into one shape so the
//!   audit chain can't tell which branch fired (matches Windows +
//!   Linux halves + C-04b policy).

use std::path::Path;

// GOLD-ARCH-08 — the AES-128-CBC decrypt loop + key derivation moved to
// `chrome_common`; these aes/cbc/sha1 imports now only feed the test module
// (the v10/v11 encrypt fixture + the iter=1 drift-guard recompute).
#[cfg(test)]
use aes::Aes128;
#[cfg(test)]
use cbc::cipher::KeyIvInit;
#[cfg(test)]
use cbc::cipher::block_padding::Pkcs7;
#[cfg(test)]
use sha1::Sha1;

// GOLD-ARCH-08 — the row/credential structs + the saltysalt/CBC envelope
// constants are shared in `chrome_common`; macOS supplies only the PBKDF2
// iteration count (1003) + the Login Keychain source.
pub use crate::credentials::chrome_common::{
    AES_KEY_BYTES, CHROME_CBC_IV, ChromeLoginRow, DecryptedChromeCredential, SALTYSALT, V10_PREFIX,
    V11_PREFIX,
};

/// PBKDF2 iteration count on macOS. Chrome hardcodes **1003** on
/// macOS for legacy compatibility (Linux uses 1, Windows uses
/// DPAPI + GCM). Do **NOT** change — would break interop with every
/// existing macOS Chrome profile.
pub const PBKDF2_ITERATIONS: u32 = 1003;

/// Keychain service name Chrome registers under. Chromium-derived
/// browsers (Brave, Vivaldi) use their own variant; we accept any
/// of the known family names.
pub const CHROME_KEYCHAIN_SERVICES: &[&str] = &[
    "Chrome Safe Storage",
    "Chromium Safe Storage",
    "Brave Safe Storage",
];

/// Keychain account name Chrome uses in every Safe Storage entry.
pub const CHROME_KEYCHAIN_ACCOUNT: &str = "Chrome";

/// Errors surfaced by the macOS Chrome decrypt path. Importer
/// collapses variants into a generic per-source diagnostic before
/// the audit chain.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ChromeMacosError {
    #[error("Keychain item lookup failed: {0}")]
    KeychainLookup(String),
    #[error("no Chrome Safe Storage item found in Login Keychain")]
    KeychainItemMissing,
    #[error("AES-128-CBC decrypt failed (wrong key or corrupt ciphertext)")]
    AesCbcDecrypt,
    #[error("password envelope unsupported format (no v10/v11 prefix)")]
    UnrecognizedBlob,
    #[error("SQLite read of Login Data failed: {0}")]
    Sqlite(String),
}

/// PBKDF2-HMAC-SHA1 with Chrome's hardcoded `"saltysalt"` salt + **1003**
/// iterations → 16-byte AES-128 key. The iteration count is the
/// per-platform pinch — macOS uses 1003 where Linux uses 1.
pub fn derive_chrome_aes_key(password: &[u8]) -> [u8; AES_KEY_BYTES] {
    // GOLD-ARCH-08 — body shared with Linux in `chrome_common`; macOS supplies
    // only its `PBKDF2_ITERATIONS` (1003) pinch.
    crate::credentials::chrome_common::derive_saltysalt_key(password, PBKDF2_ITERATIONS)
}

/// Decrypt one password BLOB. Strips v10/v11 prefix + runs AES-128-CBC
/// with the hardcoded `"                "` IV. Non-prefixed blobs
/// surface as `UnrecognizedBlob`.
pub fn decrypt_chrome_password_macos(
    aes_key: &[u8; AES_KEY_BYTES],
    blob: &[u8],
) -> Result<Vec<u8>, ChromeMacosError> {
    // GOLD-ARCH-08 — shared CBC loop lives in `chrome_common`; macOS maps the
    // generic error onto its own per-source diagnostic enum.
    use crate::credentials::chrome_common::ChromeCbcError;
    crate::credentials::chrome_common::decrypt_chrome_cbc_envelope(aes_key, blob).map_err(|e| {
        match e {
            ChromeCbcError::UnrecognizedBlob => ChromeMacosError::UnrecognizedBlob,
            ChromeCbcError::AesCbcDecrypt => ChromeMacosError::AesCbcDecrypt,
        }
    })
}

/// Look up the Chrome AES-key password in the operator's Login
/// Keychain. Tries each known service name in [`CHROME_KEYCHAIN_SERVICES`]
/// (Chrome / Chromium / Brave); returns the first hit.
///
/// macOS may surface an interactive confirmation prompt the first
/// time NEOTH accesses the keychain item. We pass through Apple's
/// default UI; silencing it would violate the operator's security
/// model.
pub fn get_chrome_password_from_keychain() -> Result<Vec<u8>, ChromeMacosError> {
    use security_framework::passwords::get_generic_password;

    let mut last_err: Option<ChromeMacosError> = None;
    for service in CHROME_KEYCHAIN_SERVICES {
        match get_generic_password(service, CHROME_KEYCHAIN_ACCOUNT) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                last_err = Some(ChromeMacosError::KeychainLookup(format!(
                    "service={service}: {e}"
                )));
            }
        }
    }
    Err(last_err.unwrap_or(ChromeMacosError::KeychainItemMissing))
}

/// Read all rows of Chrome's `logins` table. Read-only open.
pub fn read_chrome_logins(login_data_path: &Path) -> Result<Vec<ChromeLoginRow>, ChromeMacosError> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = rusqlite::Connection::open_with_flags(login_data_path, flags)
        .map_err(|e| ChromeMacosError::Sqlite(e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| ChromeMacosError::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ChromeLoginRow {
                origin_url: row.get(0)?,
                username: row.get(1)?,
                password_blob: row.get(2)?,
            })
        })
        .map_err(|e| ChromeMacosError::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| ChromeMacosError::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

/// Full discover orchestration: pulls the keychain password, derives
/// the AES key, opens Login Data, decrypts every row. Per-entry
/// failures fold into the `warnings` Vec; whole-flow failures (no
/// keychain item / SQLite open failed / etc.) surface as `Err`.
pub async fn discover_chrome_credentials_macos(
    login_data_path: &Path,
) -> Result<(Vec<DecryptedChromeCredential>, Vec<String>), ChromeMacosError> {
    // get_chrome_password_from_keychain is sync (security-framework
    // is sync) — wrap in spawn_blocking so the async executor isn't
    // blocked while the keychain UI prompts.
    let password = tokio::task::spawn_blocking(get_chrome_password_from_keychain)
        .await
        .map_err(|e| {
            ChromeMacosError::KeychainLookup(format!("blocking task join failed: {e}"))
        })??;
    let aes_key = derive_chrome_aes_key(&password);

    let path = login_data_path.to_path_buf();
    let rows = tokio::task::spawn_blocking(move || read_chrome_logins(&path))
        .await
        .map_err(|e| ChromeMacosError::Sqlite(format!("blocking task join failed: {e}")))??;

    let mut creds = Vec::with_capacity(rows.len());
    let mut warnings = Vec::new();
    for row in rows {
        match decrypt_chrome_password_macos(&aes_key, &row.password_blob) {
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

    // ── PBKDF2 KDF — KAT for iter=1003 ────────────────────────────

    #[test]
    fn derive_chrome_aes_key_known_answer_test_iter_1003() {
        // PBKDF2-HMAC-SHA1("peanuts", "saltysalt", iter=1003, dklen=16) —
        // macOS Chrome uses 1003 iterations (vs Linux's 1). Verified
        // independently with `python -c "import hashlib;
        // print(hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1003,
        // 16).hex())"` → d9a09d499b4e1b7461f28e67972c6dbd.
        let got = derive_chrome_aes_key(b"peanuts");
        let expected: [u8; 16] = [
            0xd9, 0xa0, 0x9d, 0x49, 0x9b, 0x4e, 0x1b, 0x74, 0x61, 0xf2, 0x8e, 0x67, 0x97, 0x2c,
            0x6d, 0xbd,
        ];
        assert_eq!(
            got, expected,
            "macOS Chrome PBKDF2('peanuts', iter=1003) KAT must match"
        );
    }

    #[test]
    fn derive_chrome_aes_key_differs_from_linux_iter_1() {
        // Critical drift guard: macOS uses iter=1003, NOT iter=1
        // like Linux. If a future code change accidentally unified
        // the iteration counts, this test fails.
        let macos_key = derive_chrome_aes_key(b"peanuts");
        // Manually compute the iter=1 variant (matches chrome_linux).
        let mut linux_key = [0u8; 16];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"peanuts", SALTYSALT, 1, &mut linux_key);
        assert_ne!(
            macos_key, linux_key,
            "macOS iter=1003 MUST diverge from Linux iter=1"
        );
    }

    #[test]
    fn derive_chrome_aes_key_different_passwords_diverge() {
        let a = derive_chrome_aes_key(b"password1");
        let b = derive_chrome_aes_key(b"password2");
        assert_ne!(a, b);
    }

    // ── v10/v11 envelope round-trip ───────────────────────────────

    #[test]
    fn decrypt_chrome_password_macos_v10_round_trip() {
        let key: [u8; 16] = [0x42; 16];
        let plaintext = b"macos-safe-storage-secret";
        let blob = build_v10_envelope(&key, plaintext, V10_PREFIX);
        let recovered = decrypt_chrome_password_macos(&key, &blob).expect("v10 round-trip");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_macos_v11_round_trip() {
        let key: [u8; 16] = [0x55; 16];
        let plaintext = b"macos-v11-data";
        let blob = build_v10_envelope(&key, plaintext, V11_PREFIX);
        let recovered = decrypt_chrome_password_macos(&key, &blob).expect("v11 round-trip");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_macos_wrong_key_returns_err() {
        let key: [u8; 16] = [0x42; 16];
        let wrong: [u8; 16] = [0x43; 16];
        let blob = build_v10_envelope(&key, b"data", V10_PREFIX);
        let mut got_err = false;
        for nudge in 0..8 {
            let mut b = blob.clone();
            b[3] ^= nudge;
            if decrypt_chrome_password_macos(&wrong, &b).is_err() {
                got_err = true;
                break;
            }
        }
        assert!(got_err, "wrong key MUST surface as Err in 8 trials");
    }

    #[test]
    fn decrypt_chrome_password_macos_unrecognized_prefix_returns_err() {
        let key: [u8; 16] = [0; 16];
        let blob = vec![0x01, 0x02, 0x03, 0x04];
        let err = decrypt_chrome_password_macos(&key, &blob).unwrap_err();
        assert_eq!(err, ChromeMacosError::UnrecognizedBlob);
    }

    #[test]
    fn decrypt_chrome_password_macos_end_to_end_with_derived_key() {
        // Integration: derive AES key from a fake keychain password
        // using the real PBKDF2 (iter=1003), build a v10 envelope,
        // decrypt with the same key. Pins the full path a real
        // import would exercise.
        let fake_keychain_password = b"random-keychain-pw-32-bytes-aaa";
        let aes_key = derive_chrome_aes_key(fake_keychain_password);
        let plaintext = b"macos-end-to-end-test";
        let blob = build_v10_envelope(&aes_key, plaintext, V10_PREFIX);
        let recovered = decrypt_chrome_password_macos(&aes_key, &blob).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn constants_are_canonical() {
        assert_eq!(V10_PREFIX, b"v10");
        assert_eq!(V11_PREFIX, b"v11");
        assert_eq!(SALTYSALT, b"saltysalt");
        assert_eq!(CHROME_CBC_IV.as_slice(), b"                ");
        assert_eq!(CHROME_CBC_IV.len(), 16);
        assert_eq!(PBKDF2_ITERATIONS, 1003, "macOS iter MUST be 1003");
        assert_eq!(AES_KEY_BYTES, 16);
        assert_eq!(CHROME_KEYCHAIN_ACCOUNT, "Chrome");
        // Service-name list must cover the Chromium family.
        assert!(CHROME_KEYCHAIN_SERVICES.contains(&"Chrome Safe Storage"));
        assert!(CHROME_KEYCHAIN_SERVICES.contains(&"Chromium Safe Storage"));
        assert!(CHROME_KEYCHAIN_SERVICES.contains(&"Brave Safe Storage"));
    }
}
