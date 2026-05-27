//! C-03b Windows — Chrome `Login Data` decrypt via DPAPI + AES-256-GCM.
//!
//! Modern Chrome (since 2018) wraps each saved password in an
//! AES-GCM envelope; the symmetric key lives DPAPI-wrapped inside
//! `Local State`. Legacy Chrome (pre-2018) skipped the GCM layer and
//! DPAPI'd the password directly — that path stays supported as a
//! fallback for operators with pre-migration profiles.
//!
//! ## Envelope shapes
//!
//! ### v10 / v11 envelope (modern, post-2018)
//!
//! ```text
//! [0..3]   "v10"  or  "v11"   (3 bytes — selects key-source variant)
//! [3..15]  AES-GCM nonce      (12 bytes)
//! [15..]   ciphertext || tag  (last 16 bytes = GCM auth tag)
//! ```
//!
//! The `Local State` JSON file at
//! `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` holds
//! `os_crypt.encrypted_key` — base64-encoded `[b"DPAPI", DPAPI_blob]`.
//! `CryptUnprotectData` unwraps the DPAPI blob to the raw 32-byte
//! AES-256-GCM key.
//!
//! ### Legacy envelope (pre-2018)
//!
//! Raw DPAPI blob; the entire `password_value` column is passed to
//! `CryptUnprotectData`. No version prefix.
//!
//! ## Algorithm-correction note
//!
//! The handoff doc lists AES-GCM as the v10 cipher but a future
//! Chrome update could move to ChaCha20-Poly1305 (their public roadmap
//! mentioned this for v12). When that lands, add a `V12_PREFIX` arm
//! to [`decrypt_chrome_password`] — the dispatch is OID-equivalent.
//!
//! ## Side-channel hygiene
//!
//! - **Constant-time tag verify** — `aes-gcm 0.10` uses `subtle::ct_eq`
//!   internally for the Poly1305 tag compare; we don't add another
//!   check on top.
//! - **Single Err variant for crypto fail** — `AesGcmDecrypt` collapses
//!   wrong-key / tag-mismatch / corrupt-ciphertext into one shape so
//!   the audit chain can't tell which branch fired (matches C-04b
//!   policy + the per-OS importer hard rules).

use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use serde::Deserialize;

/// First 3 bytes of the modern Chrome password envelope (v10).
pub const V10_PREFIX: &[u8] = b"v10";

/// First 3 bytes of the v11 password envelope (App-Bound Encryption
/// — Chrome 127+). Same AES-GCM body shape; selects a different
/// `Local State` key source on Chrome internally. We don't need to
/// distinguish — the dispatched decrypt is identical.
pub const V11_PREFIX: &[u8] = b"v11";

/// First 5 bytes of the `Local State` `encrypted_key` field after
/// base64 decode. NSS-style sentinel that announces "the rest is a
/// DPAPI blob — strip me + call CryptUnprotectData".
pub const DPAPI_PREFIX: &[u8] = b"DPAPI";

/// Errors surfaced by the Windows Chrome decrypt path. Importer
/// collapses variants into a generic per-source diagnostic before
/// the audit chain — the variant differentiation here exists for
/// operator-visible wizard warnings + drift-guard tests.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ChromeWindowsError {
    // NB: `io_error` not `source` — thiserror auto-detects a field
    // named `source` as a `#[source]` error-chain pointer + requires
    // it to impl `std::error::Error`. We carry the error as a String
    // (no original `io::Error` retained) so use a non-magic name.
    #[error("Local State JSON file read failed at {path}: {io_error}")]
    LocalStateRead { path: String, io_error: String },
    #[error("Local State JSON parse failed: {0}")]
    LocalStateJson(String),
    #[error("Local State encrypted_key field base64 decode failed: {0}")]
    EncryptedKeyBase64(String),
    #[error("Local State encrypted_key missing the 'DPAPI' prefix (got {got_len} bytes)")]
    EncryptedKeyPrefixMissing { got_len: usize },
    #[error("DPAPI CryptUnprotectData failed (Win32 error code {0})")]
    DpapiDecrypt(u32),
    #[error("AES-GCM decrypt failed (wrong key, corrupt ciphertext, or tag mismatch)")]
    AesGcmDecrypt,
    #[error("password envelope too short: {got} bytes (need >= 31)")]
    BlobTooShort { got: usize },
    #[error("master key wrong length: got {got} bytes, expected 32 (AES-256)")]
    MasterKeyWrongLength { got: usize },
    #[error("password plaintext not UTF-8: {0}")]
    PasswordNotUtf8(String),
    #[error("SQLite read of Login Data failed: {0}")]
    Sqlite(String),
}

/// One row from Chrome's `logins` table — the raw shape before
/// decrypt. `password_blob` is either a v10/v11 envelope or a bare
/// DPAPI blob; [`decrypt_chrome_password`] picks the right path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeLoginRow {
    pub origin_url: String,
    pub username: String,
    pub password_blob: Vec<u8>,
}

#[derive(Deserialize)]
struct LocalStateOsCrypt {
    encrypted_key: String,
}

#[derive(Deserialize)]
struct LocalState {
    os_crypt: LocalStateOsCrypt,
}

/// Parse a `Local State` JSON body and DPAPI-unwrap the embedded
/// AES-256-GCM key. Returns the raw 32-byte key ready for
/// [`decrypt_chrome_password`].
pub fn read_local_state_aes_key(local_state_path: &Path) -> Result<[u8; 32], ChromeWindowsError> {
    let body = std::fs::read_to_string(local_state_path).map_err(|e| {
        ChromeWindowsError::LocalStateRead {
            path: local_state_path.display().to_string(),
            io_error: e.to_string(),
        }
    })?;
    parse_and_unwrap_aes_key(&body)
}

/// Parse a `Local State` JSON body (already-loaded variant) and
/// DPAPI-unwrap the embedded AES-256-GCM key. Split from
/// [`read_local_state_aes_key`] so tests can hand-craft synthetic
/// JSON bodies without writing a real file.
pub fn parse_and_unwrap_aes_key(body: &str) -> Result<[u8; 32], ChromeWindowsError> {
    use base64::Engine;
    let parsed: LocalState = serde_json::from_str(body)
        .map_err(|e| ChromeWindowsError::LocalStateJson(e.to_string()))?;
    let encrypted_key = base64::engine::general_purpose::STANDARD
        .decode(parsed.os_crypt.encrypted_key.trim())
        .map_err(|e| ChromeWindowsError::EncryptedKeyBase64(e.to_string()))?;
    if !encrypted_key.starts_with(DPAPI_PREFIX) {
        return Err(ChromeWindowsError::EncryptedKeyPrefixMissing {
            got_len: encrypted_key.len(),
        });
    }
    let dpapi_blob = &encrypted_key[DPAPI_PREFIX.len()..];
    let raw_key = dpapi_decrypt(dpapi_blob)?;
    let raw_key_len = raw_key.len();
    let key: [u8; 32] = raw_key
        .try_into()
        .map_err(|_| ChromeWindowsError::MasterKeyWrongLength { got: raw_key_len })?;
    Ok(key)
}

/// Decrypt one password BLOB from Chrome's `password_value` column.
/// Dispatches on the leading 3 bytes: v10/v11 envelope → AES-GCM
/// with the supplied `aes_key`; anything else → bare DPAPI.
pub fn decrypt_chrome_password(
    aes_key: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, ChromeWindowsError> {
    if blob.starts_with(V10_PREFIX) || blob.starts_with(V11_PREFIX) {
        // v10/v11 envelope: 3-byte prefix + 12-byte nonce + ciphertext + 16-byte GCM tag.
        // Minimum size 3 + 12 + 16 = 31 (a 0-byte plaintext is technically valid).
        if blob.len() < 3 + 12 + 16 {
            return Err(ChromeWindowsError::BlobTooShort { got: blob.len() });
        }
        let nonce_bytes: &[u8; 12] = (&blob[3..15])
            .try_into()
            .expect("slice 3..15 is exactly 12 bytes by construction");
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext_with_tag = &blob[15..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| ChromeWindowsError::AesGcmDecrypt)
    } else {
        // Legacy bare DPAPI path. Pre-2018 Chrome installs that
        // never migrated to the v10 envelope still land here.
        dpapi_decrypt(blob)
    }
}

/// Wrap `CryptUnprotectData` with safe FFI. Returns the plaintext on
/// success; surfaces the Win32 error code on failure so the
/// operator-visible wizard warning can include something actionable.
///
/// Only compiled on Windows targets — the surrounding module is
/// `#[cfg(target_os = "windows")]`-gated in `credentials/mod.rs`.
pub fn dpapi_decrypt(blob: &[u8]) -> Result<Vec<u8>, ChromeWindowsError> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: `in_blob.pbData` aliases the caller's `blob` slice;
    // `CryptUnprotectData` documents the input as read-only despite
    // the non-const-pointer-typed DATA_BLOB field, and windows-sys
    // exposes the input slot as `*const CRYPT_INTEGER_BLOB`. The
    // optional `*const`/`*mut` slots accept NULL (documented as
    // optional in the Win32 reference). `out_blob` is OS-allocated;
    // we LocalFree it before returning.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is always safe.
        let err = unsafe { GetLastError() };
        return Err(ChromeWindowsError::DpapiDecrypt(err));
    }
    // Copy the plaintext bytes BEFORE LocalFree-ing the buffer so
    // we don't hand back a slice into freed memory.
    let plaintext =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    // SAFETY: out_blob.pbData was allocated by CryptUnprotectData;
    // LocalFree is the documented release primitive.
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(plaintext)
}

/// Read all rows of Chrome's `logins` table. Opens the database
/// read-only so a concurrent Chrome process holding a write lock
/// doesn't block us (and we never accidentally mutate the operator's
/// profile).
pub fn read_chrome_logins(
    login_data_path: &Path,
) -> Result<Vec<ChromeLoginRow>, ChromeWindowsError> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = rusqlite::Connection::open_with_flags(login_data_path, flags)
        .map_err(|e| ChromeWindowsError::Sqlite(e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| ChromeWindowsError::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ChromeLoginRow {
                origin_url: row.get(0)?,
                username: row.get(1)?,
                password_blob: row.get(2)?,
            })
        })
        .map_err(|e| ChromeWindowsError::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| ChromeWindowsError::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

/// One decrypted Chrome credential the importer surfaces. `password`
/// is the UTF-8 decoded plaintext; non-UTF-8 entries (Chrome stores
/// passwords as bytes — operator might have a binary password) get
/// folded into a per-entry warning by the caller and are not surfaced
/// in the entries list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedChromeCredential {
    pub origin_url: String,
    pub username: String,
    pub password: String,
}

/// Full discover orchestration: read Local State + Login Data, unwrap
/// the AES-256-GCM master key, decrypt every row. Used by
/// `chrome::ChromeImporter::discover_entries` on Windows. Per-entry
/// failures fold into the `warnings` Vec; whole-flow failures (missing
/// Local State / DPAPI denied / SQLite open failed) surface as `Err`.
///
/// Returns `(credentials, warnings)`. Warnings are operator-visible
/// "skipped entry for X because Y" strings.
pub fn discover_chrome_credentials_windows(
    login_data_path: &Path,
    local_state_path: &Path,
) -> Result<(Vec<DecryptedChromeCredential>, Vec<String>), ChromeWindowsError> {
    let aes_key = read_local_state_aes_key(local_state_path)?;
    let rows = read_chrome_logins(login_data_path)?;
    let mut creds = Vec::with_capacity(rows.len());
    let mut warnings = Vec::new();
    for row in rows {
        match decrypt_chrome_password(&aes_key, &row.password_blob) {
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

    /// Build a synthetic v10 envelope: prefix + nonce + AES-GCM
    /// encrypt(plaintext) under a known key. Test helper for the
    /// decrypt_chrome_password round-trip.
    fn build_v10_envelope(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        prefix: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_obj = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, plaintext)
            .expect("synthetic encrypt must succeed");
        let mut blob = Vec::with_capacity(prefix.len() + nonce.len() + ciphertext.len());
        blob.extend_from_slice(prefix);
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&ciphertext);
        blob
    }

    // ── v10 envelope round-trip ────────────────────────────────────

    #[test]
    fn decrypt_chrome_password_v10_round_trip() {
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0xAB; 12];
        let plaintext = b"super-secret-password-123";
        let blob = build_v10_envelope(&key, &nonce, plaintext, V10_PREFIX);
        let recovered = decrypt_chrome_password(&key, &blob).expect("v10 round-trip must work");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_v11_round_trip() {
        // v11 envelope dispatches to the same AES-GCM body decode —
        // the only difference is which Local State key field Chrome
        // would use internally. From our perspective (we already
        // have the unwrapped key in hand) both prefixes behave the
        // same way.
        let key: [u8; 32] = [0x55; 32];
        let nonce: [u8; 12] = [0xCD; 12];
        let plaintext = b"v11-path-plaintext";
        let blob = build_v10_envelope(&key, &nonce, plaintext, V11_PREFIX);
        let recovered = decrypt_chrome_password(&key, &blob).expect("v11 round-trip must work");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_chrome_password_wrong_key_returns_err() {
        // Side-channel pin: wrong key collapses to AesGcmDecrypt
        // (single variant — no differentiation between "wrong key"
        // and "tag mismatch" so the audit chain can't leak which
        // branch fired).
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0xAB; 12];
        let plaintext = b"data";
        let blob = build_v10_envelope(&key, &nonce, plaintext, V10_PREFIX);
        let wrong_key: [u8; 32] = [0x43; 32];
        let err = decrypt_chrome_password(&wrong_key, &blob).unwrap_err();
        assert_eq!(err, ChromeWindowsError::AesGcmDecrypt);
    }

    #[test]
    fn decrypt_chrome_password_truncated_blob_returns_err() {
        // < 31 bytes (3 prefix + 12 nonce + 16 tag) is structurally
        // impossible — surface as BlobTooShort before the AES path.
        let key: [u8; 32] = [0; 32];
        let truncated = vec![b'v', b'1', b'0', 0x00, 0x01]; // 5 bytes
        let err = decrypt_chrome_password(&key, &truncated).unwrap_err();
        match err {
            ChromeWindowsError::BlobTooShort { got } => assert_eq!(got, 5),
            other => panic!("expected BlobTooShort, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_chrome_password_tampered_ciphertext_returns_err() {
        // Critical drift guard: a single-bit flip in the ciphertext
        // MUST surface as AesGcmDecrypt — never decrypt to garbage
        // bytes that the importer would then accept as a password.
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0xAB; 12];
        let mut blob = build_v10_envelope(&key, &nonce, b"original", V10_PREFIX);
        // Flip a bit somewhere in the ciphertext (not the tag tail).
        let tamper_idx = 15 + 1;
        blob[tamper_idx] ^= 0x01;
        let err = decrypt_chrome_password(&key, &blob).unwrap_err();
        assert_eq!(err, ChromeWindowsError::AesGcmDecrypt);
    }

    #[test]
    fn decrypt_chrome_password_empty_plaintext_round_trip() {
        // Edge: 0-byte plaintext is valid in AES-GCM. Resulting blob
        // is exactly 31 bytes (3 prefix + 12 nonce + 16 tag).
        let key: [u8; 32] = [0x99; 32];
        let nonce: [u8; 12] = [0x88; 12];
        let blob = build_v10_envelope(&key, &nonce, b"", V10_PREFIX);
        assert_eq!(blob.len(), 31, "empty-plaintext blob is 31 bytes");
        let recovered = decrypt_chrome_password(&key, &blob).unwrap();
        assert!(recovered.is_empty());
    }

    // ── Local State JSON parse ────────────────────────────────────

    /// Build a fake Local State JSON body containing the supplied
    /// `encrypted_key` (already base64-encoded).
    fn local_state_json(encrypted_key_b64: &str) -> String {
        format!(
            r#"{{
                "os_crypt": {{
                    "encrypted_key": "{}"
                }},
                "unrelated_field": "ignored"
            }}"#,
            encrypted_key_b64
        )
    }

    #[test]
    fn parse_and_unwrap_aes_key_rejects_malformed_json() {
        let err = parse_and_unwrap_aes_key("not json").unwrap_err();
        assert!(matches!(err, ChromeWindowsError::LocalStateJson(_)));
    }

    #[test]
    fn parse_and_unwrap_aes_key_rejects_missing_os_crypt() {
        let err = parse_and_unwrap_aes_key(r#"{"other": "data"}"#).unwrap_err();
        assert!(matches!(err, ChromeWindowsError::LocalStateJson(_)));
    }

    #[test]
    fn parse_and_unwrap_aes_key_rejects_invalid_base64() {
        let body = local_state_json("not!valid!base64!");
        let err = parse_and_unwrap_aes_key(&body).unwrap_err();
        assert!(matches!(err, ChromeWindowsError::EncryptedKeyBase64(_)));
    }

    #[test]
    fn parse_and_unwrap_aes_key_rejects_missing_dpapi_prefix() {
        use base64::Engine;
        let raw_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
        let body = local_state_json(&b64);
        let err = parse_and_unwrap_aes_key(&body).unwrap_err();
        match err {
            ChromeWindowsError::EncryptedKeyPrefixMissing { got_len } => {
                assert_eq!(got_len, 5);
            }
            other => panic!("expected EncryptedKeyPrefixMissing, got {other:?}"),
        }
    }

    // ── DPAPI round-trip (Windows-only — needs real CryptProtectData) ─

    #[cfg(windows)]
    fn dpapi_encrypt(plaintext: &[u8]) -> Vec<u8> {
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};

        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &mut out_blob,
            )
        };
        assert_ne!(ok, 0, "CryptProtectData must succeed in test env");
        let cipher = unsafe {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pbData as _);
        }
        cipher
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_decrypt_round_trips_known_plaintext() {
        let plaintext = b"a chrome master key 32 bytes!!!!"; // 32 bytes
        let cipher = dpapi_encrypt(plaintext);
        let recovered = dpapi_decrypt(&cipher).expect("DPAPI round-trip must work");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[cfg(windows)]
    #[test]
    fn parse_and_unwrap_aes_key_end_to_end_dpapi() {
        use base64::Engine;
        // Build a synthetic Local State by DPAPI-encrypting a known
        // 32-byte master key, prepending the "DPAPI" sentinel, and
        // base64-encoding the whole thing. This exercises every
        // layer (JSON parse → base64 decode → prefix strip → DPAPI
        // unwrap → length check).
        let raw_key: [u8; 32] = [0xCC; 32];
        let dpapi_blob = dpapi_encrypt(&raw_key);
        let mut combined = Vec::with_capacity(DPAPI_PREFIX.len() + dpapi_blob.len());
        combined.extend_from_slice(DPAPI_PREFIX);
        combined.extend_from_slice(&dpapi_blob);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
        let body = local_state_json(&b64);
        let recovered = parse_and_unwrap_aes_key(&body).expect("end-to-end must work");
        assert_eq!(recovered, raw_key);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_decrypt_rejects_corrupt_blob() {
        // Random garbage isn't a valid DPAPI ciphertext. Win32
        // surfaces ERROR_INVALID_DATA (13) or similar; we just
        // need DpapiDecrypt variant.
        let garbage = vec![0xFFu8; 64];
        let err = dpapi_decrypt(&garbage).unwrap_err();
        assert!(
            matches!(err, ChromeWindowsError::DpapiDecrypt(_)),
            "expected DpapiDecrypt, got {err:?}"
        );
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn prefix_constants_are_canonical() {
        assert_eq!(V10_PREFIX, b"v10");
        assert_eq!(V11_PREFIX, b"v11");
        assert_eq!(DPAPI_PREFIX, b"DPAPI");
        assert_eq!(V10_PREFIX.len(), 3);
        assert_eq!(V11_PREFIX.len(), 3);
        assert_eq!(DPAPI_PREFIX.len(), 5);
    }
}
