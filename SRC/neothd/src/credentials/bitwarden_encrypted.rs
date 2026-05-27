//! C-02b (Session 28) — encrypted Bitwarden JSON export decrypt.
//!
//! Bitwarden's encrypted (password-protected) export wraps the same
//! payload shape as the unencrypted export (vault items as JSON)
//! under a password-derived AES-256-CBC + HMAC-SHA256 envelope. The
//! PBKDF2-SHA256 KDF variant (`kdfType = 0`) is the default for
//! exports from the Bitwarden web vault + covers ~99% of operator
//! exports. Argon2id (`kdfType = 1`) is a follow-up.
//!
//! ## Envelope JSON shape
//!
//! ```json
//! {
//!   "encrypted": true,
//!   "passwordProtected": true,
//!   "salt": "<string — used as raw bytes>",
//!   "kdfType": 0,
//!   "kdfIterations": 600000,
//!   "kdfMemory": null,
//!   "kdfParallelism": null,
//!   "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
//!   "data": "2.iv|ct|mac"
//! }
//! ```
//!
//! ## Crypto flow
//!
//! ```text
//! 1. master_key = PBKDF2-HMAC-SHA256(password_bytes, salt_bytes,
//!                                    iter=kdfIterations, dklen=32)
//! 2. enc_key    = HKDF-Expand-SHA256(prk=master_key, info=b"enc", L=32)
//!    mac_key    = HKDF-Expand-SHA256(prk=master_key, info=b"mac", L=32)
//! 3. Verify `encKeyValidation_DO_NOT_EDIT`:
//!      - Parse "2.iv|ct|mac" → iv (b64), ct (b64), mac (b64).
//!      - Recompute `HMAC-SHA256(mac_key, iv||ct)` + constant-time
//!        compare with `mac` (subtle::ConstantTimeEq).
//!      - Decrypt `AES-256-CBC(enc_key, iv, ct)` → plaintext.
//!      - Wrong password fails at HMAC compare OR PKCS#7 unpad —
//!        collapse both to `WrongPassword`.
//! 4. Decrypt `data` the same way → unencrypted JSON of vault items.
//! ```
//!
//! ## Side-channel hygiene
//!
//! - **Constant-time HMAC compare** via `subtle::ConstantTimeEq` — a
//!   `==` byte compare would leak via timing-side channel under
//!   brute force.
//! - **Collapsed wrong-password variants** — `WrongPassword` covers
//!   HMAC mismatch + AES-CBC unpad fail + downstream parse fail so
//!   the audit chain can't tell which branch fired (matches C-04b +
//!   C-03b side-channel policy).
//! - **No salt over-trust** — `salt` field is whatever string
//!   Bitwarden put there (often the operator's account email).
//!   We pass it through verbatim as PBKDF2 salt bytes; no length
//!   minimum enforced because Bitwarden itself doesn't enforce one.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Bitwarden's "2." prefix on encrypted strings selects the
/// AES-256-CBC + HMAC-SHA256 cipher suite. Other prefixes ("0.",
/// "1.", "3.", "4.") exist in the broader Bitwarden ecosystem but
/// the password-protected export always emits "2.".
pub const ENCRYPTION_TYPE_AES_CBC_HMAC: &str = "2";

/// `kdfType` value for PBKDF2-SHA256 (default + most common).
pub const KDF_TYPE_PBKDF2: u32 = 0;

/// `kdfType` value for Argon2id (newer Bitwarden installs). NOT
/// supported in this module yet — surfaces as `UnsupportedKdf` so
/// the operator gets an actionable error instead of a wrong-password
/// false negative.
pub const KDF_TYPE_ARGON2ID: u32 = 1;

/// Decoded envelope shape from a Bitwarden encrypted export. `salt`
/// is the raw bytes used as PBKDF2 salt — Bitwarden stores it as a
/// UTF-8 string (often the operator's account email).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedExportEnvelope {
    pub salt: Vec<u8>,
    pub kdf_type: u32,
    pub kdf_iterations: u32,
    pub enc_key_validation: String,
    pub data: String,
}

/// Errors surfaced by [`parse_and_decrypt`]. Importer collapses
/// every variant into one shape before reaching the audit chain.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BitwardenEncryptedError {
    #[error("JSON parse failed: {0}")]
    JsonParse(String),
    #[error("export is not encrypted (no `encrypted: true` field)")]
    NotEncrypted,
    #[error("export is encrypted but not password-protected (account-key path unsupported)")]
    AccountKeyNotSupported,
    #[error("unsupported kdfType {0} (supported: 0 = PBKDF2)")]
    UnsupportedKdf(u32),
    #[error("kdfIterations {0} below the Bitwarden minimum (100_000)")]
    IterationsTooLow(u32),
    #[error("encrypted-string format invalid: {0}")]
    EncryptedStringFormat(String),
    #[error("base64 decode failed: {0}")]
    Base64(String),
    #[error("primary password rejected (HMAC verification failed)")]
    WrongPassword,
}

#[derive(Deserialize)]
struct EncryptedExportRaw {
    #[serde(default)]
    encrypted: bool,
    #[serde(rename = "passwordProtected", default)]
    password_protected: bool,
    #[serde(default)]
    salt: String,
    #[serde(rename = "kdfType", default)]
    kdf_type: u32,
    #[serde(rename = "kdfIterations", default)]
    kdf_iterations: u32,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT", default)]
    enc_key_validation: String,
    #[serde(default)]
    data: String,
}

/// Parse the JSON envelope of a Bitwarden encrypted export. Does not
/// touch crypto — just validates the shape + extracts the fields.
pub fn parse_envelope_json(body: &str) -> Result<EncryptedExportEnvelope, BitwardenEncryptedError> {
    let raw: EncryptedExportRaw = serde_json::from_str(body)
        .map_err(|e| BitwardenEncryptedError::JsonParse(e.to_string()))?;
    if !raw.encrypted {
        return Err(BitwardenEncryptedError::NotEncrypted);
    }
    if !raw.password_protected {
        return Err(BitwardenEncryptedError::AccountKeyNotSupported);
    }
    if raw.kdf_type != KDF_TYPE_PBKDF2 {
        return Err(BitwardenEncryptedError::UnsupportedKdf(raw.kdf_type));
    }
    if raw.kdf_iterations < 100_000 {
        // Bitwarden's documented minimum is 100_000 (newer accounts
        // use 600_000 by default). Below this is a misconfigured or
        // corrupt export — reject rather than running brute-force-
        // friendly iterations.
        return Err(BitwardenEncryptedError::IterationsTooLow(
            raw.kdf_iterations,
        ));
    }
    Ok(EncryptedExportEnvelope {
        salt: raw.salt.into_bytes(),
        kdf_type: raw.kdf_type,
        kdf_iterations: raw.kdf_iterations,
        enc_key_validation: raw.enc_key_validation,
        data: raw.data,
    })
}

/// Derive the (enc_key, mac_key) pair from the operator's password +
/// the envelope's salt + iteration count. Two-step KDF: PBKDF2 →
/// HKDF-Expand. Pure-fn — testable without crypto-context setup.
pub fn derive_keys_pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 32]) {
    let mut master_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut master_key);
    // HKDF-Expand only (no Extract phase) — Bitwarden uses the
    // PBKDF2 output directly as the PRK.
    let hk = Hkdf::<Sha256>::from_prk(&master_key).expect("32-byte PRK is valid for Hkdf-SHA256");
    let mut enc_key = [0u8; 32];
    hk.expand(b"enc", &mut enc_key)
        .expect("32 bytes fits in the 8160-byte HKDF output bound");
    let mut mac_key = [0u8; 32];
    hk.expand(b"mac", &mut mac_key)
        .expect("32 bytes fits in the 8160-byte HKDF output bound");
    (enc_key, mac_key)
}

/// Decode a Bitwarden encrypted-string "2.iv|ct|mac" into its three
/// raw byte fields. Pure-fn — used by both the validator + the data
/// decrypt paths.
pub fn parse_encrypted_string(
    s: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), BitwardenEncryptedError> {
    use base64::Engine;
    let (kind, rest) = s.split_once('.').ok_or_else(|| {
        BitwardenEncryptedError::EncryptedStringFormat("missing `<type>.` prefix".to_string())
    })?;
    if kind != ENCRYPTION_TYPE_AES_CBC_HMAC {
        return Err(BitwardenEncryptedError::EncryptedStringFormat(format!(
            "unsupported encryption type `{kind}` (expected `2`)"
        )));
    }
    let parts: Vec<&str> = rest.split('|').collect();
    if parts.len() != 3 {
        return Err(BitwardenEncryptedError::EncryptedStringFormat(format!(
            "expected 3 pipe-separated fields (iv|ct|mac), got {}",
            parts.len()
        )));
    }
    let iv = base64::engine::general_purpose::STANDARD
        .decode(parts[0])
        .map_err(|e| BitwardenEncryptedError::Base64(format!("iv: {e}")))?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| BitwardenEncryptedError::Base64(format!("ciphertext: {e}")))?;
    let mac = base64::engine::general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|e| BitwardenEncryptedError::Base64(format!("mac: {e}")))?;
    if iv.len() != 16 {
        return Err(BitwardenEncryptedError::EncryptedStringFormat(format!(
            "IV must be 16 bytes (AES-CBC), got {}",
            iv.len()
        )));
    }
    if mac.len() != 32 {
        return Err(BitwardenEncryptedError::EncryptedStringFormat(format!(
            "MAC must be 32 bytes (HMAC-SHA256), got {}",
            mac.len()
        )));
    }
    Ok((iv, ct, mac))
}

/// Decrypt a Bitwarden encrypted-string ("2.iv|ct|mac") with the
/// supplied enc_key + mac_key. Verifies the HMAC in constant time
/// before invoking the AES-CBC decrypt — wrong-password / tampered-
/// ciphertext collapse to `WrongPassword`.
pub fn decrypt_encrypted_string(
    encrypted: &str,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Vec<u8>, BitwardenEncryptedError> {
    let (iv, ct, mac) = parse_encrypted_string(encrypted)?;
    let mut hmac = HmacSha256::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key len");
    hmac.update(&iv);
    hmac.update(&ct);
    let computed_mac = hmac.finalize().into_bytes();
    if !bool::from(computed_mac.ct_eq(mac.as_slice())) {
        return Err(BitwardenEncryptedError::WrongPassword);
    }
    let iv_arr: [u8; 16] = iv
        .as_slice()
        .try_into()
        .expect("iv.len() checked == 16 above");
    let mut buf = ct.clone();
    let pt = Aes256CbcDec::new(enc_key.into(), &iv_arr.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| BitwardenEncryptedError::WrongPassword)?;
    Ok(pt.to_vec())
}

/// End-to-end: parse the envelope, derive the keys from `password`,
/// verify via the `encKeyValidation_DO_NOT_EDIT` round-trip, then
/// decrypt the `data` field. Returns the unencrypted vault-items
/// JSON ready for the existing `credentials::bitwarden::parse_export_str`
/// path.
///
/// Wrong-password (most common operator error) surfaces as a single
/// `BitwardenEncryptedError::WrongPassword` regardless of which
/// internal step caught it.
pub fn parse_and_decrypt(body: &str, password: &str) -> Result<String, BitwardenEncryptedError> {
    let envelope = parse_envelope_json(body)?;
    let (enc_key, mac_key) =
        derive_keys_pbkdf2(password.as_bytes(), &envelope.salt, envelope.kdf_iterations);
    // Step 1: validator round-trip. encKeyValidation contains a
    // self-referential encrypted ciphertext — when decrypted, the
    // plaintext bytes equal the SAME encKeyValidation string. A
    // wrong password fails HMAC or PKCS#7 unpad here.
    let validator_pt = decrypt_encrypted_string(&envelope.enc_key_validation, &enc_key, &mac_key)?;
    if validator_pt != envelope.enc_key_validation.as_bytes() {
        return Err(BitwardenEncryptedError::WrongPassword);
    }
    // Step 2: the actual vault data.
    let data_pt = decrypt_encrypted_string(&envelope.data, &enc_key, &mac_key)?;
    String::from_utf8(data_pt).map_err(|e| {
        BitwardenEncryptedError::EncryptedStringFormat(format!(
            "decrypted data not UTF-8 ({})",
            e.utf8_error()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    fn build_encrypted_string(
        plaintext: &[u8],
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        iv: &[u8; 16],
    ) -> String {
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes256CbcEnc::new(enc_key.into(), iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("encrypt must succeed")
            .len();
        buf.truncate(ct_len);
        let mut hmac =
            HmacSha256::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key len");
        hmac.update(iv);
        hmac.update(&buf);
        let mac = hmac.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(iv),
            base64::engine::general_purpose::STANDARD.encode(&buf),
            base64::engine::general_purpose::STANDARD.encode(mac),
        )
    }

    fn build_synthetic_export(
        password: &str,
        salt: &str,
        iters: u32,
        data_plaintext: &str,
    ) -> String {
        let (enc_key, mac_key) = derive_keys_pbkdf2(password.as_bytes(), salt.as_bytes(), iters);
        let iv: [u8; 16] = [0xAB; 16];
        // encKeyValidation: decrypt-yields-itself contract.
        let validator_plain = String::new(); // placeholder; we'll loop
        // Two-step: build the validator with placeholder, get its
        // actual encrypted string, then USE that string as its own
        // plaintext + re-encrypt. Saves a hand-derived constant.
        let validator = build_encrypted_string(validator_plain.as_bytes(), &enc_key, &mac_key, &iv);
        let validator_self_referential =
            build_encrypted_string(validator.as_bytes(), &enc_key, &mac_key, &iv);
        let iv2: [u8; 16] = [0xCD; 16];
        let data_enc = build_encrypted_string(data_plaintext.as_bytes(), &enc_key, &mac_key, &iv2);
        format!(
            r#"{{
                "encrypted": true,
                "passwordProtected": true,
                "salt": "{salt}",
                "kdfType": 0,
                "kdfIterations": {iters},
                "kdfMemory": null,
                "kdfParallelism": null,
                "encKeyValidation_DO_NOT_EDIT": "{validator_self_referential}",
                "data": "{data_enc}"
            }}"#
        )
    }

    // ── parse_envelope_json ───────────────────────────────────────

    #[test]
    fn parse_envelope_canonical_shape() {
        let body = r#"{
            "encrypted": true,
            "passwordProtected": true,
            "salt": "alex@example.com",
            "kdfType": 0,
            "kdfIterations": 600000,
            "encKeyValidation_DO_NOT_EDIT": "2.aaa|bbb|ccc",
            "data": "2.ddd|eee|fff"
        }"#;
        let env = parse_envelope_json(body).unwrap();
        assert_eq!(env.salt, b"alex@example.com");
        assert_eq!(env.kdf_type, 0);
        assert_eq!(env.kdf_iterations, 600000);
    }

    #[test]
    fn parse_envelope_rejects_unencrypted_export() {
        let body = r#"{"encrypted": false, "items": []}"#;
        let err = parse_envelope_json(body).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::NotEncrypted);
    }

    #[test]
    fn parse_envelope_rejects_account_key_path() {
        let body = r#"{
            "encrypted": true,
            "passwordProtected": false,
            "salt": "",
            "kdfType": 0,
            "kdfIterations": 600000,
            "encKeyValidation_DO_NOT_EDIT": "2.a|b|c",
            "data": "2.a|b|c"
        }"#;
        let err = parse_envelope_json(body).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::AccountKeyNotSupported);
    }

    #[test]
    fn parse_envelope_rejects_argon2id() {
        let body = r#"{
            "encrypted": true,
            "passwordProtected": true,
            "salt": "x",
            "kdfType": 1,
            "kdfIterations": 3,
            "encKeyValidation_DO_NOT_EDIT": "2.a|b|c",
            "data": "2.a|b|c"
        }"#;
        let err = parse_envelope_json(body).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::UnsupportedKdf(1));
    }

    #[test]
    fn parse_envelope_rejects_low_iterations() {
        let body = r#"{
            "encrypted": true,
            "passwordProtected": true,
            "salt": "x",
            "kdfType": 0,
            "kdfIterations": 5000,
            "encKeyValidation_DO_NOT_EDIT": "2.a|b|c",
            "data": "2.a|b|c"
        }"#;
        let err = parse_envelope_json(body).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::IterationsTooLow(5000));
    }

    // ── derive_keys_pbkdf2 ────────────────────────────────────────

    #[test]
    fn derive_keys_distinct_enc_and_mac() {
        let (enc, mac) = derive_keys_pbkdf2(b"pw", b"salt", 100_000);
        assert_ne!(enc, mac, "enc + mac must differ (different HKDF info)");
    }

    #[test]
    fn derive_keys_deterministic() {
        let a = derive_keys_pbkdf2(b"pw", b"salt", 100_000);
        let b = derive_keys_pbkdf2(b"pw", b"salt", 100_000);
        assert_eq!(a, b, "same inputs → same outputs");
    }

    #[test]
    fn derive_keys_diverge_on_distinct_password() {
        let a = derive_keys_pbkdf2(b"pw1", b"salt", 100_000);
        let b = derive_keys_pbkdf2(b"pw2", b"salt", 100_000);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_keys_diverge_on_distinct_salt() {
        let a = derive_keys_pbkdf2(b"pw", b"salt1", 100_000);
        let b = derive_keys_pbkdf2(b"pw", b"salt2", 100_000);
        assert_ne!(a, b);
    }

    // ── parse_encrypted_string ────────────────────────────────────

    #[test]
    fn parse_encrypted_string_canonical() {
        // 16-byte IV (b'A' * 16) + 16-byte ct (b'B' * 16) + 32-byte mac (b'C' * 32) — base64.
        use base64::Engine;
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode([b'A'; 16]);
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode([b'B'; 16]);
        let mac_b64 = base64::engine::general_purpose::STANDARD.encode([b'C'; 32]);
        let s = format!("2.{iv_b64}|{ct_b64}|{mac_b64}");
        let (iv, ct, mac) = parse_encrypted_string(&s).unwrap();
        assert_eq!(iv, vec![b'A'; 16]);
        assert_eq!(ct, vec![b'B'; 16]);
        assert_eq!(mac, vec![b'C'; 32]);
    }

    #[test]
    fn parse_encrypted_string_rejects_wrong_type() {
        let err = parse_encrypted_string("0.a|b|c").unwrap_err();
        assert!(matches!(
            err,
            BitwardenEncryptedError::EncryptedStringFormat(_)
        ));
    }

    #[test]
    fn parse_encrypted_string_rejects_missing_dot() {
        let err = parse_encrypted_string("aaaa").unwrap_err();
        assert!(matches!(
            err,
            BitwardenEncryptedError::EncryptedStringFormat(_)
        ));
    }

    #[test]
    fn parse_encrypted_string_rejects_wrong_arity() {
        use base64::Engine;
        let s = format!(
            "2.{}|{}",
            base64::engine::general_purpose::STANDARD.encode([b'A'; 16]),
            base64::engine::general_purpose::STANDARD.encode([b'B'; 16]),
        );
        let err = parse_encrypted_string(&s).unwrap_err();
        match err {
            BitwardenEncryptedError::EncryptedStringFormat(m) => {
                assert!(m.contains("3 pipe-separated"));
            }
            other => panic!("expected EncryptedStringFormat, got {other:?}"),
        }
    }

    #[test]
    fn parse_encrypted_string_rejects_wrong_iv_len() {
        use base64::Engine;
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode([b'A'; 8]); // 8 not 16
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode([b'B'; 16]);
        let mac_b64 = base64::engine::general_purpose::STANDARD.encode([b'C'; 32]);
        let s = format!("2.{iv_b64}|{ct_b64}|{mac_b64}");
        let err = parse_encrypted_string(&s).unwrap_err();
        match err {
            BitwardenEncryptedError::EncryptedStringFormat(m) => {
                assert!(m.contains("IV must be 16"))
            }
            other => panic!("expected IV-length error, got {other:?}"),
        }
    }

    // ── decrypt_encrypted_string ──────────────────────────────────

    #[test]
    fn decrypt_encrypted_string_round_trip() {
        let enc_key: [u8; 32] = [0x42; 32];
        let mac_key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let plaintext = b"vault-items-json-here";
        let s = build_encrypted_string(plaintext, &enc_key, &mac_key, &iv);
        let recovered = decrypt_encrypted_string(&s, &enc_key, &mac_key).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn decrypt_encrypted_string_wrong_mac_key_returns_wrong_password() {
        let enc_key: [u8; 32] = [0x42; 32];
        let right_mac: [u8; 32] = [0x55; 32];
        let wrong_mac: [u8; 32] = [0x56; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let s = build_encrypted_string(b"data", &enc_key, &right_mac, &iv);
        let err = decrypt_encrypted_string(&s, &enc_key, &wrong_mac).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::WrongPassword);
    }

    #[test]
    fn decrypt_encrypted_string_wrong_enc_key_returns_wrong_password() {
        // HMAC matches (we use the right mac_key) but enc_key is wrong
        // → AES-CBC decrypt produces garbage; PKCS#7 unpad almost
        // certainly fails. Collapses to WrongPassword.
        let enc_key: [u8; 32] = [0x42; 32];
        let wrong_enc: [u8; 32] = [0x43; 32];
        let mac_key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        // 8-perturbation defence (lifted from C-04b + C-03b pattern).
        let mut got_err = false;
        for nudge in 0..8u8 {
            let mut iv_perturbed = iv;
            iv_perturbed[0] ^= nudge;
            let s = build_encrypted_string(b"sensitive", &enc_key, &mac_key, &iv_perturbed);
            if decrypt_encrypted_string(&s, &wrong_enc, &mac_key).is_err() {
                got_err = true;
                break;
            }
        }
        assert!(got_err, "wrong enc_key MUST surface as Err in 8 trials");
    }

    #[test]
    fn decrypt_encrypted_string_tampered_ciphertext_returns_wrong_password() {
        use base64::Engine;
        let enc_key: [u8; 32] = [0x42; 32];
        let mac_key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let s = build_encrypted_string(b"original", &enc_key, &mac_key, &iv);
        // Tamper: flip a bit in the ciphertext segment. Re-encode.
        let parts: Vec<&str> = s.split('.').nth(1).unwrap().split('|').collect();
        let mut ct = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .unwrap();
        ct[0] ^= 0x01;
        let tampered = format!(
            "2.{}|{}|{}",
            parts[0],
            base64::engine::general_purpose::STANDARD.encode(&ct),
            parts[2],
        );
        let err = decrypt_encrypted_string(&tampered, &enc_key, &mac_key).unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::WrongPassword);
    }

    // ── parse_and_decrypt end-to-end ──────────────────────────────

    #[test]
    fn parse_and_decrypt_round_trips_synthetic_export() {
        let password = "correct-horse-battery";
        let salt = "alex@example.com";
        let iters = 100_000;
        let data_plain =
            r#"{"items":[{"name":"PayPal","login":{"username":"alex","password":"hunter2"}}]}"#;
        let body = build_synthetic_export(password, salt, iters, data_plain);
        let recovered = parse_and_decrypt(&body, password).unwrap();
        assert_eq!(recovered, data_plain);
    }

    #[test]
    fn parse_and_decrypt_rejects_wrong_password() {
        let body = build_synthetic_export("right", "salt", 100_000, "{\"items\":[]}");
        let err = parse_and_decrypt(&body, "wrong").unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::WrongPassword);
    }

    #[test]
    fn parse_and_decrypt_propagates_envelope_error() {
        let body = r#"{"encrypted": false, "items": []}"#;
        let err = parse_and_decrypt(body, "anypw").unwrap_err();
        assert_eq!(err, BitwardenEncryptedError::NotEncrypted);
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn constants_are_canonical() {
        assert_eq!(ENCRYPTION_TYPE_AES_CBC_HMAC, "2");
        assert_eq!(KDF_TYPE_PBKDF2, 0);
        assert_eq!(KDF_TYPE_ARGON2ID, 1);
    }
}
