//! C-04b Phase 2 chunk 2a (Session 27) — Firefox `key4.db` crypto primitives.
//!
//! `key4.db` is the SQLite database NSS writes the master-key
//! envelope + the operator's password check string into. The full
//! decrypt flow reads two columns:
//!
//! - `metaData.item2` — PBES2-wrapped "password-check" plaintext
//!   (`b"password-check"`); decrypts iff the operator's primary
//!   password is correct. Used as a wrong-password detector
//!   before attempting the master-key unwrap (the master-key
//!   unwrap itself would also fail on the wrong password but
//!   the failure surfaces as a generic AES-CBC unpad error —
//!   the `metaData.item2` check has a specific plaintext we can
//!   verify against, so it's the operator-friendly gate).
//! - `nssPrivate.a11` — PBES2-wrapped 24-byte master key, also
//!   AES-256-CBC under the same masking key.
//!
//! Chunk 2a (this file) ships the two cryptographic primitives
//! that don't need the SQLite read: the PBKDF2-SHA256 masking-key
//! derivation + the password-check verifier. Both are NIST-/RFC-
//! KAT-pinned so a future regression in the underlying RustCrypto
//! crates surfaces here, not in the integration test.
//!
//! Chunk 2b (Session 28) wires `rusqlite` to read the two
//! key4.db columns + the ASN.1 PBES2 envelope decoder (a
//! 2-layer SEQUENCE, slightly more complex than the SECITEM
//! envelope shipped by `firefox_envelope` chunk 1) + the
//! end-to-end `extract_master_key` orchestration.
//!
//! ## Chunk 2b deliverables (this revision)
//!
//! - [`Key4DbReader`] trait — abstract surface for the two SQLite
//!   reads (`metaData.item1`+`item2` and `nssPrivate.a11`). Lets
//!   tests stub the reads without touching disk.
//! - [`RusqliteKey4DbReader`] — concrete impl backed by the
//!   bundled `rusqlite` SQLite library.
//! - [`derive_intermediate_key`] — NSS's KDF preamble:
//!   `SHA-1(global_salt || primary_password)`. The 20-byte output
//!   becomes the *password* input to PBKDF2 (NOT the operator's
//!   raw password). This is the NSS-specific quirk that every
//!   `firefox_decrypt` derivative implements.
//! - [`extract_master_key`] — full orchestration: reads both
//!   columns → parses both PBES2 envelopes → derives intermediate
//!   key → unwraps the password-check (gates on wrong-password)
//!   → unwraps the master key blob.
//! - [`extract_master_key_from_file`] — convenience wrapper for
//!   the wizard chunk 3 path that just hands over the on-disk
//!   `key4.db` path + the operator-prompted primary password.

use std::path::Path;

use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::credentials::firefox_pbes2::{Pbes2Envelope, Pbes2Error, parse_pbes2_envelope};

/// Canonical plaintext of the `metaData.item2` password-check
/// column. After AES-256-CBC decrypt with the right masking
/// key, the unpadded bytes equal this constant. Wrong password
/// → decrypt yields garbage → constant-time compare returns
/// false without revealing where the mismatch occurred.
pub const PASSWORD_CHECK_PLAINTEXT: &[u8] = b"password-check";

/// PBKDF2-SHA256 masking-key derivation. NSS 3.40+ uses 10_000
/// iterations as the default for fresh key4.db creates; older
/// profiles may carry whatever the wizard at-create-time picked,
/// so the caller passes `iterations` from the metadata table
/// rather than hardcoding.
///
/// Returns a 32-byte key suitable for AES-256-CBC. The output
/// length is fixed because every NSS code path expects 32 bytes;
/// surfacing a different length would only be a footgun.
pub fn derive_masking_key_pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    // pbkdf2_hmac is infallible in pbkdf2 0.12 — no Result wrap.
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    key
}

/// Verify the operator's primary password by attempting to
/// decrypt the `metaData.item2` ciphertext and comparing the
/// plaintext (in constant time) against [`PASSWORD_CHECK_PLAINTEXT`].
///
/// Returns `true` iff the masking key recovers the canonical
/// check string. Returns `false` for every failure mode —
/// decrypt-fails / pad-fails / plaintext-doesn't-match all
/// collapse to the same `false` so an attacker timing the
/// caller can't distinguish "wrong password" from "corrupt
/// envelope" from "unsupported algorithm".
///
/// `iv` is the 16-byte IV extracted from the PBES2 envelope's
/// AlgorithmIdentifier; chunk 2b feeds it from the ASN.1 decode.
pub fn verify_password_check(
    masking_key: &[u8; 32],
    iv: &[u8; 16],
    check_ciphertext: &[u8],
) -> bool {
    match crate::credentials::firefox::decrypt_aes256_cbc_pkcs7(masking_key, iv, check_ciphertext) {
        Ok(plaintext) => plaintext.ct_eq(PASSWORD_CHECK_PLAINTEXT).into(),
        Err(_) => false,
    }
}

// ─── Chunk 2b: SQLite reader trait + extract_master_key ───────────────────

/// One `metaData` row containing the operator's primary-password
/// gate. NSS stores it under `id = 'password'`: `item1` carries the
/// global salt, `item2` carries the PBES2-wrapped password-check
/// ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaDataPasswordRow {
    /// Global salt mixed with the primary password during the SHA-1
    /// KDF preamble. NSS emits 20 bytes; we accept any non-empty len.
    pub global_salt: Vec<u8>,
    /// BER-encoded PBES2 envelope wrapping the canonical
    /// `b"password-check"` plaintext.
    pub password_check_envelope: Vec<u8>,
}

/// Errors surfaced by [`extract_master_key`] and the SQLite reads it
/// chains. The audit chain MUST collapse every variant into a single
/// `Failed` outcome before WAL emission — variant differentiation is
/// for operator-visible wizard warnings + drift-guard tests only.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum MasterKeyError {
    #[error("SQLite read failed: {0}")]
    Sqlite(String),
    #[error("required key4.db row missing: {0}")]
    RowMissing(String),
    #[error("PBES2 envelope parse failed: {0}")]
    EnvelopeParse(String),
    #[error("primary password rejected by NSS password-check")]
    WrongPassword,
    #[error("master-key AES-CBC decrypt failed (envelope corrupt or wrong password)")]
    Decrypt,
    #[error("master-key blob too short: got {got} bytes, expected at least {min}")]
    MasterKeyTooShort { got: usize, min: usize },
}

impl From<Pbes2Error> for MasterKeyError {
    fn from(e: Pbes2Error) -> Self {
        Self::EnvelopeParse(e.to_string())
    }
}

/// Trait the orchestration calls into for the two `key4.db` SQLite
/// reads. Production code uses [`RusqliteKey4DbReader`]; tests stub
/// it to inject synthetic envelopes without touching disk.
pub trait Key4DbReader {
    /// `SELECT item1, item2 FROM metaData WHERE id = 'password'`.
    ///
    /// Returns `RowMissing` if the row is absent (no primary-password
    /// gate ever set, or the file is not a valid key4.db).
    fn read_metadata_password_row(&self) -> Result<MetaDataPasswordRow, MasterKeyError>;

    /// `SELECT a11 FROM nssPrivate ORDER BY id LIMIT 1`.
    ///
    /// Returns the BER-encoded PBES2 envelope wrapping the master
    /// key blob. Returns `RowMissing` when `nssPrivate` is empty
    /// (a key4.db built from a profile that never generated a master
    /// key — pathological but observable on freshly-initialised
    /// profiles).
    fn read_master_key_envelope(&self) -> Result<Vec<u8>, MasterKeyError>;
}

/// Concrete [`Key4DbReader`] backed by a bundled `rusqlite`
/// connection. Opens the file read-only so a concurrent Firefox
/// process holding a write lock doesn't block us (and we don't
/// accidentally mutate the operator's profile).
pub struct RusqliteKey4DbReader {
    conn: rusqlite::Connection,
}

impl RusqliteKey4DbReader {
    /// Open a read-only connection to the operator's `key4.db`.
    ///
    /// The `OpenFlags::SQLITE_OPEN_READ_ONLY` flag is required —
    /// Firefox holds a write lock on its own key4.db while running,
    /// and read-write open would surface as a `database locked` error.
    pub fn open(path: &Path) -> Result<Self, MasterKeyError> {
        use rusqlite::OpenFlags;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let conn = rusqlite::Connection::open_with_flags(path, flags)
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Wrap an already-opened connection (used by in-memory tests
    /// where the synthetic DB is built up before being handed off).
    pub fn from_connection(conn: rusqlite::Connection) -> Self {
        Self { conn }
    }
}

impl Key4DbReader for RusqliteKey4DbReader {
    fn read_metadata_password_row(&self) -> Result<MetaDataPasswordRow, MasterKeyError> {
        let mut stmt = self
            .conn
            .prepare("SELECT item1, item2 FROM metaData WHERE id = 'password'")
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        let row = rows
            .next()
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?
            .ok_or_else(|| {
                MasterKeyError::RowMissing("metaData row with id='password'".to_string())
            })?;
        let global_salt: Vec<u8> = row
            .get(0)
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        let password_check_envelope: Vec<u8> = row
            .get(1)
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        Ok(MetaDataPasswordRow {
            global_salt,
            password_check_envelope,
        })
    }

    fn read_master_key_envelope(&self) -> Result<Vec<u8>, MasterKeyError> {
        let mut stmt = self
            .conn
            .prepare("SELECT a11 FROM nssPrivate ORDER BY id LIMIT 1")
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        let row = rows
            .next()
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?
            .ok_or_else(|| MasterKeyError::RowMissing("nssPrivate.a11 row".to_string()))?;
        let envelope: Vec<u8> = row
            .get(0)
            .map_err(|e| MasterKeyError::Sqlite(e.to_string()))?;
        Ok(envelope)
    }
}

/// NSS KDF preamble: `SHA-1(global_salt || primary_password)`. The
/// 20-byte output becomes the *password* input to PBKDF2 — not the
/// operator's raw password. This is a quirk specific to NSS's
/// PBES2 implementation; every `firefox_decrypt` derivative reproduces
/// the same chain.
///
/// The function is `pub` so the wizard chunk-3 path can compute the
/// intermediate key once + reuse it across multiple PBES2 envelopes
/// (the password-check envelope + the master-key envelope share the
/// same global salt + primary password).
pub fn derive_intermediate_key(global_salt: &[u8], primary_password: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(global_salt);
    hasher.update(primary_password);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// Decrypt the payload of a PBES2 envelope using a pre-computed
/// intermediate key. Returns the unpadded plaintext on success.
///
/// Internal helper — the two callers (password-check verify +
/// master-key unwrap) share this code path so the AES-CBC primitive
/// is invoked the same way + with the same NSS IV-quirk handling
/// in both branches.
fn decrypt_pbes2_payload(
    envelope: &Pbes2Envelope,
    intermediate_key: &[u8; 20],
) -> Result<Vec<u8>, MasterKeyError> {
    // PBKDF2-HMAC-SHA256(intermediate_key, kdf_salt, iters) → masking key.
    let mut masking_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        intermediate_key,
        &envelope.kdf_salt,
        envelope.kdf_iters,
        &mut masking_key,
    );
    let iv = envelope.full_aes_cbc_iv();
    crate::credentials::firefox::decrypt_aes256_cbc_pkcs7(&masking_key, &iv, &envelope.ciphertext)
        .map_err(|_| MasterKeyError::Decrypt)
}

/// End-to-end orchestration: pull both key4.db rows via the reader,
/// parse both PBES2 envelopes, derive the intermediate key from the
/// global salt + primary password, verify the password-check (gates
/// on wrong-password), then unwrap the master key blob.
///
/// Returns the full master-key blob (variable length: 24 bytes for
/// legacy 3DES, 32 bytes for modern AES-256-CBC; the SECITEM-envelope
/// algorithm OID at decrypt time tells the caller which slice to use).
///
/// Constant-time gate: the password-check uses
/// [`verify_password_check`] which compares with `subtle::ct_eq`. A
/// wrong primary password collapses to `MasterKeyError::WrongPassword`
/// — the audit chain MUST not differentiate this from
/// `MasterKeyError::Decrypt` (the master-key unwrap failure mode for
/// the same wrong-password case).
pub fn extract_master_key<R: Key4DbReader>(
    reader: &R,
    primary_password: &str,
) -> Result<Vec<u8>, MasterKeyError> {
    let metadata = reader.read_metadata_password_row()?;
    let password_check_env = parse_pbes2_envelope(&metadata.password_check_envelope)?;
    let master_key_env_bytes = reader.read_master_key_envelope()?;
    let master_key_env = parse_pbes2_envelope(&master_key_env_bytes)?;

    let intermediate = derive_intermediate_key(&metadata.global_salt, primary_password.as_bytes());

    // Step 1: verify the primary password by decrypting the
    // password-check envelope and checking the canonical plaintext.
    let check_plaintext = decrypt_pbes2_payload(&password_check_env, &intermediate)
        .map_err(|_| MasterKeyError::WrongPassword)?;
    if !bool::from(check_plaintext.ct_eq(PASSWORD_CHECK_PLAINTEXT)) {
        return Err(MasterKeyError::WrongPassword);
    }

    // Step 2: unwrap the master key blob. Reuse the same
    // intermediate key — both envelopes carry their own salt + iters
    // so PBKDF2 produces a different masking key per envelope.
    let master_key = decrypt_pbes2_payload(&master_key_env, &intermediate)?;
    if master_key.len() < 24 {
        return Err(MasterKeyError::MasterKeyTooShort {
            got: master_key.len(),
            min: 24,
        });
    }
    Ok(master_key)
}

/// Convenience wrapper for the wizard chunk-3 path: opens the
/// on-disk `key4.db` via the bundled rusqlite (read-only, won't
/// fight a running Firefox's write lock) and runs the full
/// [`extract_master_key`] orchestration.
pub fn extract_master_key_from_file(
    key4_db_path: &Path,
    primary_password: &str,
) -> Result<Vec<u8>, MasterKeyError> {
    let reader = RusqliteKey4DbReader::open(key4_db_path)?;
    extract_master_key(&reader, primary_password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// Encrypt a plaintext with AES-256-CBC + PKCS#7 padding —
    /// helper for the password-check verifier tests so we don't
    /// depend on a hand-typed ciphertext blob.
    fn aes_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes256CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("encrypt must succeed")
            .len();
        buf.truncate(ct_len);
        buf
    }

    // ── PBKDF2-SHA256 KAT ─────────────────────────────────────────

    #[test]
    fn pbkdf2_sha256_known_answer_test_1_iter() {
        // Published PBKDF2-HMAC-SHA256 test vector (cross-referenced
        // against multiple independent implementations including
        // OpenSSL's evp_kdf-pbkdf2 + Bouncy Castle):
        //   Password   = "password"
        //   Salt       = "salt"
        //   Iterations = 1
        //   Output     = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
        let got = derive_masking_key_pbkdf2_sha256(b"password", b"salt", 1);
        let expected: [u8; 32] = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(got, expected, "PBKDF2-SHA256 1-iter KAT must match");
    }

    #[test]
    fn pbkdf2_sha256_known_answer_test_2_iter() {
        // Same source: iters=2 produces a distinct output. Pin so a
        // pbkdf2-crate regression that silently swaps SHA-1 for
        // SHA-256 (or vice versa) fails here.
        //   Output (iters=2) = ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
        let got = derive_masking_key_pbkdf2_sha256(b"password", b"salt", 2);
        let expected: [u8; 32] = [
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0,
            0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a,
            0x95, 0x47, 0x4c, 0x43,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn pbkdf2_sha256_empty_password_does_not_panic() {
        // Operator with no primary password set → empty bytes. NSS
        // still runs PBKDF2 against the salt + iters from the
        // metadata. The wrapper must accept empty input.
        let got = derive_masking_key_pbkdf2_sha256(b"", b"some-salt", 100);
        // Sanity: not the all-zeros key (would mean the wrapper
        // skipped PBKDF2 entirely).
        assert_ne!(got, [0u8; 32]);
    }

    #[test]
    fn pbkdf2_sha256_different_iters_diverge() {
        // Drift guard: iters parameter is actually wired. A
        // regression that ignored iters (e.g. always used 1) would
        // produce identical outputs across iters values.
        let a = derive_masking_key_pbkdf2_sha256(b"pw", b"salt", 10);
        let b = derive_masking_key_pbkdf2_sha256(b"pw", b"salt", 100);
        assert_ne!(a, b, "iters must influence the derived key");
    }

    // ── verify_password_check ─────────────────────────────────────

    #[test]
    fn verify_password_check_accepts_right_key() {
        // Round-trip: encrypt "password-check" with a known key,
        // verifier must accept the same key.
        let key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&key, &iv, PASSWORD_CHECK_PLAINTEXT);
        assert!(verify_password_check(&key, &iv, &ct));
    }

    #[test]
    fn verify_password_check_rejects_wrong_key() {
        // Different key with same IV + ciphertext → verifier
        // returns false. No panic, no Err — collapses to false so
        // the side-channel surface is minimal.
        let right_key: [u8; 32] = [0x55; 32];
        let wrong_key: [u8; 32] = [0x56; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&right_key, &iv, PASSWORD_CHECK_PLAINTEXT);
        // Re-roll cap of 8 — wrong key has tiny chance of producing
        // valid PKCS#7 padding AND matching "password-check"
        // (~256^-14 — astronomical). Re-rolling perturbs the IV so
        // each trial is independent.
        let mut all_rejected = true;
        for nudge in 0..8 {
            let mut iv_perturbed = iv;
            iv_perturbed[0] ^= nudge;
            if verify_password_check(&wrong_key, &iv_perturbed, &ct) {
                all_rejected = false;
                break;
            }
        }
        assert!(all_rejected, "wrong key MUST be rejected in 8 trials");
    }

    #[test]
    fn verify_password_check_rejects_wrong_plaintext_at_right_key() {
        // Right key, but the ciphertext encrypts a DIFFERENT
        // plaintext. Decrypt succeeds (valid pad) but the
        // constant-time compare against "password-check" fails.
        // This is the critical drift guard: a wrong-PLAINTEXT
        // attack (operator tampers with key4.db to plant a
        // different but well-padded blob) must surface as false,
        // not true.
        let key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&key, &iv, b"NOT-password-check");
        assert!(
            !verify_password_check(&key, &iv, &ct),
            "right key + wrong plaintext MUST return false"
        );
    }

    #[test]
    fn verify_password_check_rejects_empty_ciphertext() {
        // Edge case: empty ciphertext can't decrypt to anything;
        // verifier must surface false (not panic).
        let key: [u8; 32] = [0; 32];
        let iv: [u8; 16] = [0; 16];
        assert!(!verify_password_check(&key, &iv, &[]));
    }

    #[test]
    fn password_check_plaintext_is_canonical_constant() {
        // Pin the constant so a future find-and-replace doesn't
        // silently mutate it. NSS firefox_decrypt + the Mozilla
        // source both use the literal bytes "password-check"
        // (14 bytes, no NUL, no length prefix).
        assert_eq!(PASSWORD_CHECK_PLAINTEXT, b"password-check");
        assert_eq!(PASSWORD_CHECK_PLAINTEXT.len(), 14);
    }

    // ── Chunk 2b: derive_intermediate_key + extract_master_key ────

    /// Deterministic helper: builds a synthetic in-memory key4.db
    /// with a known primary password, known global salt + known
    /// master-key blob. Returns the seed material so the test can
    /// assert what `extract_master_key` recovers.
    struct SyntheticKey4Db {
        global_salt: Vec<u8>,
        primary_password: String,
        master_key: Vec<u8>,
        password_check_envelope: Vec<u8>,
        master_key_envelope: Vec<u8>,
    }

    impl Key4DbReader for SyntheticKey4Db {
        fn read_metadata_password_row(&self) -> Result<MetaDataPasswordRow, MasterKeyError> {
            Ok(MetaDataPasswordRow {
                global_salt: self.global_salt.clone(),
                password_check_envelope: self.password_check_envelope.clone(),
            })
        }

        fn read_master_key_envelope(&self) -> Result<Vec<u8>, MasterKeyError> {
            Ok(self.master_key_envelope.clone())
        }
    }

    fn build_envelope(
        intermediate: &[u8; 20],
        kdf_salt: &[u8],
        iters: u32,
        iv_inner: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        // Derive masking key the same way extract_master_key will.
        let mut masking_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(intermediate, kdf_salt, iters, &mut masking_key);
        // Build the full 16-byte IV (NSS quirk).
        let mut full_iv = [0u8; 16];
        full_iv[0] = 0x04;
        full_iv[1] = 0x0e;
        full_iv[2..].copy_from_slice(iv_inner);
        // Encrypt the plaintext.
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes256CbcEnc::new(&masking_key.into(), &full_iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("synthetic encrypt must succeed")
            .len();
        buf.truncate(ct_len);
        // Wrap as PBES2 envelope.
        crate::credentials::firefox_pbes2::encode_pbes2_envelope_for_tests(
            kdf_salt, iters, 32, iv_inner, &buf,
        )
    }

    fn synthetic_db(primary_password: &str, master_key: &[u8]) -> SyntheticKey4Db {
        let global_salt = vec![0x42; 20];
        let intermediate = derive_intermediate_key(&global_salt, primary_password.as_bytes());
        let pc_envelope = build_envelope(
            &intermediate,
            &[0xAB; 20],
            10_000,
            &[0xCD; 14],
            PASSWORD_CHECK_PLAINTEXT,
        );
        let mk_envelope =
            build_envelope(&intermediate, &[0xFF; 20], 10_000, &[0x11; 14], master_key);
        SyntheticKey4Db {
            global_salt,
            primary_password: primary_password.to_string(),
            master_key: master_key.to_vec(),
            password_check_envelope: pc_envelope,
            master_key_envelope: mk_envelope,
        }
    }

    #[test]
    fn extract_master_key_recovers_known_key_with_right_password() {
        let expected_master_key = vec![0x99u8; 32];
        let db = synthetic_db("CorrectHorseBattery", &expected_master_key);
        let recovered = extract_master_key(&db, &db.primary_password)
            .expect("right password must recover master key");
        assert_eq!(recovered, expected_master_key);
    }

    #[test]
    fn extract_master_key_supports_empty_primary_password() {
        // Vast majority of operators don't set a primary password.
        // The PBKDF2 input is then SHA1(global_salt || ""), which is
        // a stable 20-byte digest of just global_salt. Must work.
        let expected_master_key = vec![0xAAu8; 32];
        let db = synthetic_db("", &expected_master_key);
        let recovered = extract_master_key(&db, "").expect("empty password path must work");
        assert_eq!(recovered, expected_master_key);
    }

    #[test]
    fn extract_master_key_supports_24_byte_legacy_master_key() {
        // Legacy 3DES path: the master key is 24 bytes. extract_master_key
        // must surface the full blob; the SECITEM-OID dispatch picks
        // the right slice at decrypt time.
        let legacy_key = vec![0x77u8; 24];
        let db = synthetic_db("legacy", &legacy_key);
        let recovered = extract_master_key(&db, "legacy").expect("legacy path must work");
        assert_eq!(recovered, legacy_key);
    }

    #[test]
    fn extract_master_key_rejects_wrong_password() {
        let db = synthetic_db("RightPass", &[0xBB; 32]);
        let err = extract_master_key(&db, "WrongPass").unwrap_err();
        // Wrong password collapses to WrongPassword — never reveals
        // whether it failed at the password-check decrypt vs the
        // master-key decrypt. Both branches must surface the same
        // variant.
        assert_eq!(err, MasterKeyError::WrongPassword);
    }

    #[test]
    fn extract_master_key_rejects_too_short_master_key() {
        // Synthetic envelope wrapping a 16-byte blob (below the
        // 24-byte legacy 3DES minimum). Should surface MasterKeyTooShort,
        // not silently return a half-blob.
        let too_short = vec![0xCC; 16];
        let db = synthetic_db("p", &too_short);
        let err = extract_master_key(&db, "p").unwrap_err();
        match err {
            MasterKeyError::MasterKeyTooShort { got, min } => {
                assert_eq!(got, 16);
                assert_eq!(min, 24);
            }
            other => panic!("expected MasterKeyTooShort, got {other:?}"),
        }
    }

    #[test]
    fn extract_master_key_propagates_envelope_parse_failure() {
        struct CorruptDb;
        impl Key4DbReader for CorruptDb {
            fn read_metadata_password_row(&self) -> Result<MetaDataPasswordRow, MasterKeyError> {
                Ok(MetaDataPasswordRow {
                    global_salt: vec![0; 20],
                    password_check_envelope: vec![0xFF, 0xFF, 0xFF, 0xFF],
                })
            }
            fn read_master_key_envelope(&self) -> Result<Vec<u8>, MasterKeyError> {
                Ok(vec![])
            }
        }
        let err = extract_master_key(&CorruptDb, "any").unwrap_err();
        assert!(matches!(err, MasterKeyError::EnvelopeParse(_)));
    }

    #[test]
    fn extract_master_key_propagates_missing_row() {
        struct EmptyDb;
        impl Key4DbReader for EmptyDb {
            fn read_metadata_password_row(&self) -> Result<MetaDataPasswordRow, MasterKeyError> {
                Err(MasterKeyError::RowMissing("test".to_string()))
            }
            fn read_master_key_envelope(&self) -> Result<Vec<u8>, MasterKeyError> {
                Ok(vec![])
            }
        }
        let err = extract_master_key(&EmptyDb, "any").unwrap_err();
        assert!(matches!(err, MasterKeyError::RowMissing(_)));
    }

    #[test]
    fn derive_intermediate_key_known_answer_test_empty_password() {
        // SHA1("salt") = 0a4d55a8d778e5022fab701977c5d840bbc486d0.
        // Empty password concatenated with the salt is just SHA1(salt).
        let got = derive_intermediate_key(b"salt", b"");
        let expected: [u8; 20] = [
            0x0a, 0x4d, 0x55, 0xa8, 0xd7, 0x78, 0xe5, 0x02, 0x2f, 0xab, 0x70, 0x19, 0x77, 0xc5,
            0xd8, 0x40, 0xbb, 0xc4, 0x86, 0xd0,
        ];
        assert_eq!(got, expected, "SHA1('salt' || '') KAT must match");
    }

    #[test]
    fn derive_intermediate_key_concatenates_in_order() {
        // SHA1('saltpassword') != SHA1('passwordsalt'). The order
        // matters; pin so a future swap of arguments fails here, not
        // silently produces an interop-breaking key derivation.
        let a = derive_intermediate_key(b"salt", b"password");
        let b = derive_intermediate_key(b"password", b"salt");
        assert_ne!(
            a, b,
            "derive_intermediate_key must concatenate salt||password"
        );
    }

    // ── RusqliteKey4DbReader against an in-memory synthetic DB ────

    fn build_in_memory_db(db: &SyntheticKey4Db) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE metaData (id TEXT PRIMARY KEY NOT NULL, item1 BLOB, item2 BLOB);
             CREATE TABLE nssPrivate (id INTEGER PRIMARY KEY AUTOINCREMENT, a11 BLOB, a102 BLOB);",
        )
        .expect("schema create");
        conn.execute(
            "INSERT INTO metaData (id, item1, item2) VALUES ('password', ?1, ?2)",
            rusqlite::params![db.global_salt, db.password_check_envelope],
        )
        .expect("insert metaData");
        conn.execute(
            "INSERT INTO nssPrivate (a11, a102) VALUES (?1, ?2)",
            rusqlite::params![db.master_key_envelope, vec![0xF8u8; 16]],
        )
        .expect("insert nssPrivate");
        conn
    }

    #[test]
    fn rusqlite_reader_round_trips_metadata_row() {
        let synth = synthetic_db("test-pw", &[0xDE; 32]);
        let conn = build_in_memory_db(&synth);
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let row = reader.read_metadata_password_row().expect("must read");
        assert_eq!(row.global_salt, synth.global_salt);
        assert_eq!(row.password_check_envelope, synth.password_check_envelope);
    }

    #[test]
    fn rusqlite_reader_round_trips_master_key_envelope() {
        let synth = synthetic_db("test-pw", &[0xAD; 32]);
        let conn = build_in_memory_db(&synth);
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let envelope = reader.read_master_key_envelope().expect("must read");
        assert_eq!(envelope, synth.master_key_envelope);
    }

    #[test]
    fn extract_master_key_end_to_end_through_rusqlite_reader() {
        // Full round-trip: build synthetic in-memory key4.db,
        // extract via the real rusqlite reader, recover the same
        // master key. This is the integration-style test that
        // exercises every layer (PBES2 parse + SHA1 KDF preamble +
        // PBKDF2-SHA256 + AES-CBC unwrap + SQLite reads).
        let expected = vec![0x5Au8; 32];
        let synth = synthetic_db("integration-test", &expected);
        let conn = build_in_memory_db(&synth);
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let recovered =
            extract_master_key(&reader, &synth.primary_password).expect("end-to-end must work");
        assert_eq!(recovered, expected);
    }

    #[test]
    fn extract_master_key_rusqlite_rejects_wrong_password_end_to_end() {
        let synth = synthetic_db("RealPassword", &[0x12; 32]);
        let conn = build_in_memory_db(&synth);
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let err = extract_master_key(&reader, "WrongPassword").unwrap_err();
        assert_eq!(err, MasterKeyError::WrongPassword);
    }

    #[test]
    fn extract_master_key_rusqlite_missing_metadata_row_surfaces_row_missing() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE metaData (id TEXT PRIMARY KEY NOT NULL, item1 BLOB, item2 BLOB);
             CREATE TABLE nssPrivate (id INTEGER PRIMARY KEY AUTOINCREMENT, a11 BLOB, a102 BLOB);",
        )
        .unwrap();
        // Insert a metaData row with a DIFFERENT id (not 'password').
        conn.execute(
            "INSERT INTO metaData (id, item1, item2) VALUES ('other', ?1, ?2)",
            rusqlite::params![vec![0u8; 20], vec![0u8; 16]],
        )
        .unwrap();
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let err = reader.read_metadata_password_row().unwrap_err();
        assert!(
            matches!(err, MasterKeyError::RowMissing(_)),
            "missing 'password' row must surface RowMissing, got {err:?}"
        );
    }

    #[test]
    fn extract_master_key_rusqlite_missing_nss_private_surfaces_row_missing() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE metaData (id TEXT PRIMARY KEY NOT NULL, item1 BLOB, item2 BLOB);
             CREATE TABLE nssPrivate (id INTEGER PRIMARY KEY AUTOINCREMENT, a11 BLOB, a102 BLOB);",
        )
        .unwrap();
        let reader = RusqliteKey4DbReader::from_connection(conn);
        let err = reader.read_master_key_envelope().unwrap_err();
        assert!(matches!(err, MasterKeyError::RowMissing(_)));
    }
}
