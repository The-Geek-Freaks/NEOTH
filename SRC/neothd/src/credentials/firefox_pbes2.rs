//! C-04b Phase 2 chunk 2b (Session 28) — PBES2 envelope decode for
//! NSS `key4.db` columns.
//!
//! Both `metaData.item2` and `nssPrivate.a11` are BER-encoded PBES2
//! envelopes (PKCS#5 v2.0, RFC 8018 §6.2). The structural shape NSS
//! emits is more nested than the SECITEM envelope shipped in chunk 1:
//!
//! ```text
//! SEQUENCE                                                -- EncryptedData
//!   SEQUENCE                                              -- AlgorithmIdentifier (PBES2)
//!     OID 1.2.840.113549.1.5.13                           -- id-PBES2
//!     SEQUENCE                                            -- PBES2-params
//!       SEQUENCE                                          -- keyDerivationFunc AlgId
//!         OID 1.2.840.113549.1.5.12                       -- id-PBKDF2
//!         SEQUENCE                                        -- PBKDF2-params
//!           OCTET STRING (salt)                           -- typ 20 bytes
//!           INTEGER (iterationCount)
//!           INTEGER (keyLength)                           -- always 32 in NSS
//!           SEQUENCE                                      -- prf AlgId
//!             OID 1.2.840.113549.2.9                      -- hmacWithSHA256
//!             NULL
//!       SEQUENCE                                          -- encryptionScheme AlgId
//!         OID 2.16.840.1.101.3.4.1.42                     -- AES-256-CBC
//!         OCTET STRING (iv_inner)                         -- 14 bytes (NSS quirk)
//!   OCTET STRING (ciphertext)                             -- PKCS#7-padded
//! ```
//!
//! ## NSS IV quirk (critical for interop)
//!
//! NSS's PBES2 implementation stores only **14 bytes** in the IV
//! `OCTET STRING` parameter. The actual AES-CBC IV used for decrypt is
//! the **full BER encoding** of that OCTET STRING — `[0x04, 0x0e] ||
//! iv_inner` — yielding 16 bytes. This is documented in the
//! Mozilla `firefox_decrypt` reference + the `lclevy/firepwd` reference
//! that every third-party Firefox-decrypt tool descends from.
//!
//! [`Pbes2Envelope::full_aes_cbc_iv`] does the prepend so callers stay
//! NSS-quirk-free.
//!
//! ## Scope
//!
//! Strict shape enforcement: any deviation from the canonical
//! structure surfaces an `Pbes2Error::*` variant. The decoder is
//! single-purpose (NSS `key4.db` consumption) — it does not attempt
//! to cover the full PKCS#5 v2 algorithm surface (PBKDF1, RC2, etc.).
//! Unknown OIDs surface as `UnsupportedAlgorithm` so the importer can
//! warn cleanly rather than silently feeding the wrong primitive.

use simple_asn1::{ASN1Block, from_der, oid};

/// Fully decoded PBES2 envelope from a NSS `key4.db` row. Carries
/// only the parameters the master-key extraction needs — the algorithm
/// OIDs themselves are validated during parse and dropped (any
/// unexpected OID surfaces as `Pbes2Error::UnsupportedAlgorithm`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbes2Envelope {
    /// PBKDF2 salt (NSS emits 20 bytes; we accept any non-empty len).
    pub kdf_salt: Vec<u8>,
    /// PBKDF2 iteration count (NSS modern: typically 10_000+).
    pub kdf_iters: u32,
    /// Derived key length in bytes (NSS emits 32 — AES-256 key).
    pub kdf_key_length: u32,
    /// Raw bytes of the AES-CBC IV `OCTET STRING` parameter. NSS
    /// stores 14 bytes here; the full 16-byte AES-CBC IV is
    /// reconstructed via [`Self::full_aes_cbc_iv`].
    pub encryption_iv_inner: Vec<u8>,
    /// AES-256-CBC ciphertext (PKCS#7-padded).
    pub ciphertext: Vec<u8>,
}

impl Pbes2Envelope {
    /// Reconstruct the 16-byte AES-CBC IV NSS expects. The NSS
    /// implementation uses the **full BER encoding** of the IV
    /// `OCTET STRING` parameter as the AES-CBC IV — `[0x04, 0x0e]`
    /// is the BER tag (`0x04` = OCTET STRING) + length (`0x0e` = 14)
    /// followed by the 14-byte inner.
    ///
    /// Panics if `encryption_iv_inner.len() != 14`. The parser
    /// enforces this at decode time (`Pbes2Error::IvLenNotFourteen`)
    /// so a Pbes2Envelope reaching this method has already been
    /// validated.
    pub fn full_aes_cbc_iv(&self) -> [u8; 16] {
        assert_eq!(
            self.encryption_iv_inner.len(),
            14,
            "NSS PBES2 IV inner must be 14 bytes; parser enforces this",
        );
        let mut iv = [0u8; 16];
        iv[0] = 0x04;
        iv[1] = 0x0e;
        iv[2..].copy_from_slice(&self.encryption_iv_inner);
        iv
    }
}

/// Errors surfaced by [`parse_pbes2_envelope`]. Importer collapses
/// every variant into a generic `MasterKeyError::EnvelopeParse`
/// before reaching the audit chain — variant differentiation here is
/// for operator-facing log lines + drift-guard tests only.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Pbes2Error {
    #[error("ASN.1 decode failed: {0}")]
    Asn1(String),
    #[error("envelope outer block must be SEQUENCE")]
    OuterNotSequence,
    #[error("envelope SEQUENCE must hold exactly 2 fields (AlgId, ciphertext), got {got}")]
    OuterArity { got: usize },
    #[error("AlgorithmIdentifier (outer) must be SEQUENCE")]
    AlgIdNotSequence,
    #[error("AlgorithmIdentifier (outer) must hold exactly 2 fields (OID, params), got {got}")]
    AlgIdArity { got: usize },
    #[error("expected id-PBES2 OID (1.2.840.113549.1.5.13), got {got}")]
    UnsupportedAlgorithm { got: String },
    #[error("PBES2-params must be SEQUENCE")]
    Pbes2ParamsNotSequence,
    #[error("PBES2-params must hold exactly 2 fields (kdf, encryption), got {got}")]
    Pbes2ParamsArity { got: usize },
    #[error("PBKDF2 AlgorithmIdentifier must be SEQUENCE")]
    KdfAlgIdNotSequence,
    #[error("PBKDF2 AlgorithmIdentifier must hold exactly 2 fields, got {got}")]
    KdfAlgIdArity { got: usize },
    #[error("expected id-PBKDF2 OID (1.2.840.113549.1.5.12), got {got}")]
    UnsupportedKdf { got: String },
    #[error("PBKDF2-params must be SEQUENCE")]
    KdfParamsNotSequence,
    #[error("PBKDF2-params must hold exactly 4 fields (salt, iters, keyLength, prf), got {got}")]
    KdfParamsArity { got: usize },
    #[error("PBKDF2 salt must be OCTET STRING")]
    KdfSaltNotOctetString,
    #[error("PBKDF2 iterationCount must be INTEGER")]
    KdfItersNotInteger,
    #[error("PBKDF2 iterationCount must fit in u32, got {got}")]
    KdfItersOutOfRange { got: String },
    #[error("PBKDF2 keyLength must be INTEGER")]
    KdfKeyLengthNotInteger,
    #[error("PBKDF2 keyLength must fit in u32, got {got}")]
    KdfKeyLengthOutOfRange { got: String },
    #[error("PBKDF2 PRF AlgorithmIdentifier must be SEQUENCE")]
    PrfAlgIdNotSequence,
    #[error("expected hmacWithSHA256 OID (1.2.840.113549.2.9) as PRF, got {got}")]
    UnsupportedPrf { got: String },
    #[error("encryption AlgorithmIdentifier must be SEQUENCE")]
    EncAlgIdNotSequence,
    #[error("encryption AlgorithmIdentifier must hold exactly 2 fields, got {got}")]
    EncAlgIdArity { got: usize },
    #[error("expected aes256-CBC OID (2.16.840.1.101.3.4.1.42), got {got}")]
    UnsupportedEncryption { got: String },
    #[error("encryption IV must be OCTET STRING")]
    EncIvNotOctetString,
    #[error("NSS PBES2 IV inner must be exactly 14 bytes, got {got}")]
    IvLenNotFourteen { got: usize },
    #[error("ciphertext must be OCTET STRING")]
    CiphertextNotOctetString,
}

/// Parse a BER-encoded PBES2 envelope (the raw bytes of
/// `metaData.item2` or `nssPrivate.a11` as they sit in the SQLite
/// BLOB column).
///
/// Strict shape enforcement: every deviation from the NSS-emitted
/// canonical structure surfaces as `Pbes2Error::*`. The parser refuses
/// to accept "almost-valid" envelopes so a malformed file fails fast
/// instead of feeding garbage into the AES decrypt.
pub fn parse_pbes2_envelope(der: &[u8]) -> Result<Pbes2Envelope, Pbes2Error> {
    let blocks = from_der(der).map_err(|e| Pbes2Error::Asn1(e.to_string()))?;
    if blocks.is_empty() {
        return Err(Pbes2Error::OuterNotSequence);
    }
    let outer = match &blocks[0] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::OuterNotSequence),
    };
    if outer.len() != 2 {
        return Err(Pbes2Error::OuterArity { got: outer.len() });
    }

    // ── outer[0] = AlgorithmIdentifier (PBES2) ─────────────────────
    let alg_id = match &outer[0] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::AlgIdNotSequence),
    };
    if alg_id.len() != 2 {
        return Err(Pbes2Error::AlgIdArity { got: alg_id.len() });
    }
    let alg_oid = match &alg_id[0] {
        ASN1Block::ObjectIdentifier(_, oid) => oid,
        _ => return Err(Pbes2Error::AlgIdNotSequence),
    };
    let id_pbes2 = oid!(1, 2, 840, 113549, 1, 5, 13);
    if alg_oid != id_pbes2 {
        return Err(Pbes2Error::UnsupportedAlgorithm {
            got: format_oid_dotted(alg_oid),
        });
    }

    // ── PBES2-params SEQUENCE ──────────────────────────────────────
    let params = match &alg_id[1] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::Pbes2ParamsNotSequence),
    };
    if params.len() != 2 {
        return Err(Pbes2Error::Pbes2ParamsArity { got: params.len() });
    }

    // ── params[0] = keyDerivationFunc AlgId ────────────────────────
    let kdf_alg_id = match &params[0] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::KdfAlgIdNotSequence),
    };
    if kdf_alg_id.len() != 2 {
        return Err(Pbes2Error::KdfAlgIdArity {
            got: kdf_alg_id.len(),
        });
    }
    let kdf_oid = match &kdf_alg_id[0] {
        ASN1Block::ObjectIdentifier(_, oid) => oid,
        _ => return Err(Pbes2Error::KdfAlgIdNotSequence),
    };
    let id_pbkdf2 = oid!(1, 2, 840, 113549, 1, 5, 12);
    if kdf_oid != id_pbkdf2 {
        return Err(Pbes2Error::UnsupportedKdf {
            got: format_oid_dotted(kdf_oid),
        });
    }

    // ── PBKDF2-params SEQUENCE ─────────────────────────────────────
    let kdf_params = match &kdf_alg_id[1] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::KdfParamsNotSequence),
    };
    if kdf_params.len() != 4 {
        return Err(Pbes2Error::KdfParamsArity {
            got: kdf_params.len(),
        });
    }
    let kdf_salt = match &kdf_params[0] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => return Err(Pbes2Error::KdfSaltNotOctetString),
    };
    let kdf_iters = match &kdf_params[1] {
        ASN1Block::Integer(_, big) => {
            u32_from_asn1_integer(big).ok_or_else(|| Pbes2Error::KdfItersOutOfRange {
                got: big.to_string(),
            })?
        }
        _ => return Err(Pbes2Error::KdfItersNotInteger),
    };
    let kdf_key_length = match &kdf_params[2] {
        ASN1Block::Integer(_, big) => {
            u32_from_asn1_integer(big).ok_or_else(|| Pbes2Error::KdfKeyLengthOutOfRange {
                got: big.to_string(),
            })?
        }
        _ => return Err(Pbes2Error::KdfKeyLengthNotInteger),
    };
    // PRF AlgorithmIdentifier — must be hmacWithSHA256
    let prf_alg = match &kdf_params[3] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::PrfAlgIdNotSequence),
    };
    let prf_oid = match prf_alg.first() {
        Some(ASN1Block::ObjectIdentifier(_, oid)) => oid,
        _ => return Err(Pbes2Error::PrfAlgIdNotSequence),
    };
    let hmac_with_sha256 = oid!(1, 2, 840, 113549, 2, 9);
    if prf_oid != hmac_with_sha256 {
        return Err(Pbes2Error::UnsupportedPrf {
            got: format_oid_dotted(prf_oid),
        });
    }

    // ── params[1] = encryption AlgorithmIdentifier ─────────────────
    let enc_alg_id = match &params[1] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(Pbes2Error::EncAlgIdNotSequence),
    };
    if enc_alg_id.len() != 2 {
        return Err(Pbes2Error::EncAlgIdArity {
            got: enc_alg_id.len(),
        });
    }
    let enc_oid = match &enc_alg_id[0] {
        ASN1Block::ObjectIdentifier(_, oid) => oid,
        _ => return Err(Pbes2Error::EncAlgIdNotSequence),
    };
    let aes_256_cbc = oid!(2, 16, 840, 1, 101, 3, 4, 1, 42);
    if enc_oid != aes_256_cbc {
        return Err(Pbes2Error::UnsupportedEncryption {
            got: format_oid_dotted(enc_oid),
        });
    }
    let iv_inner = match &enc_alg_id[1] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => return Err(Pbes2Error::EncIvNotOctetString),
    };
    if iv_inner.len() != 14 {
        return Err(Pbes2Error::IvLenNotFourteen {
            got: iv_inner.len(),
        });
    }

    // ── outer[1] = ciphertext OCTET STRING ─────────────────────────
    let ciphertext = match &outer[1] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => return Err(Pbes2Error::CiphertextNotOctetString),
    };

    Ok(Pbes2Envelope {
        kdf_salt,
        kdf_iters,
        kdf_key_length,
        encryption_iv_inner: iv_inner,
        ciphertext,
    })
}

/// Convert an ASN.1 INTEGER to `u32`, returning `None` for negatives,
/// zero, or values above `u32::MAX`.
///
/// COR-24: the previous `to_u32_digits().1.first()` took the LOW
/// base-2^32 word of the magnitude, silently truncating any oversized
/// value — `2^33` (digits `[0, 2]`) parsed as `0`, and `2^32 + N` parsed
/// as `N`. For a credential KDF that means a forged/garbage iteration
/// count or key length sails through as a plausible small number. Accept
/// a value only when its magnitude is exactly one base-2^32 digit
/// (`1..=u32::MAX`); an empty digit list (zero — never a valid KDF work
/// factor) and any multi-digit magnitude both reject. Negatives are not
/// NSS-emitted and are rejected up front.
fn u32_from_asn1_integer(big: &simple_asn1::BigInt) -> Option<u32> {
    if big < &simple_asn1::BigInt::from(0u32) {
        return None;
    }
    match big.to_u32_digits().1.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn format_oid_dotted(oid: &simple_asn1::OID) -> String {
    match oid.as_vec::<u128>() {
        Ok(arcs) => arcs
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("."),
        Err(_) => format!("{oid:?}"),
    }
}

// ─── Test-only BER encoder ─────────────────────────────────────────
//
// Hand-rolled BER for the canonical NSS PBES2 envelope. Used by
// both the parser tests (so a hand-built fixture round-trips through
// the parser) and the `firefox_key4db` extract_master_key tests
// (where the same encoder builds the synthetic key4.db row payloads).

/// Build a BER-encoded PBES2 envelope from its parameters.
///
/// Pinned strictly to NSS's emitted shape: the PRF AlgorithmIdentifier
/// is always present (hmacWithSHA256), the encryption is AES-256-CBC,
/// the IV inner is always 14 bytes.
#[cfg(test)]
pub fn encode_pbes2_envelope_for_tests(
    kdf_salt: &[u8],
    kdf_iters: u32,
    kdf_key_length: u32,
    iv_inner: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    assert_eq!(iv_inner.len(), 14, "NSS PBES2 IV inner is always 14 bytes",);
    // ── PBKDF2-params SEQUENCE ─────────────────────────────────────
    let mut pbkdf2_params = Vec::new();
    push_octet_string(&mut pbkdf2_params, kdf_salt);
    push_integer_u32(&mut pbkdf2_params, kdf_iters);
    push_integer_u32(&mut pbkdf2_params, kdf_key_length);
    let mut prf_alg = Vec::new();
    push_oid_bytes(
        &mut prf_alg,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09],
    ); // 1.2.840.113549.2.9
    push_null(&mut prf_alg);
    push_sequence(&mut pbkdf2_params, &prf_alg);
    let mut pbkdf2_alg_id = Vec::new();
    push_oid_bytes(
        &mut pbkdf2_alg_id,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C],
    ); // 1.2.840.113549.1.5.12
    push_sequence(&mut pbkdf2_alg_id, &pbkdf2_params);

    // ── encryption AlgorithmIdentifier ─────────────────────────────
    let mut enc_alg_id = Vec::new();
    push_oid_bytes(
        &mut enc_alg_id,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
    ); // 2.16.840.1.101.3.4.1.42
    push_octet_string(&mut enc_alg_id, iv_inner);

    // ── PBES2-params SEQUENCE ──────────────────────────────────────
    let mut pbes2_params = Vec::new();
    push_sequence(&mut pbes2_params, &pbkdf2_alg_id);
    push_sequence(&mut pbes2_params, &enc_alg_id);

    // ── outer AlgorithmIdentifier (PBES2) ──────────────────────────
    let mut alg_id = Vec::new();
    push_oid_bytes(
        &mut alg_id,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D],
    ); // 1.2.840.113549.1.5.13
    push_sequence(&mut alg_id, &pbes2_params);

    // ── outer EncryptedData SEQUENCE ───────────────────────────────
    let mut outer = Vec::new();
    push_sequence(&mut outer, &alg_id);
    push_octet_string(&mut outer, ciphertext);

    let mut out = Vec::new();
    push_sequence(&mut out, &outer);
    out
}

#[cfg(test)]
fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        panic!("BER length > 65535 unsupported in test encoder");
    }
}

#[cfg(test)]
fn push_sequence(out: &mut Vec<u8>, body: &[u8]) {
    out.push(0x30);
    push_length(out, body.len());
    out.extend_from_slice(body);
}

#[cfg(test)]
fn push_octet_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(0x04);
    push_length(out, bytes.len());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
fn push_oid_bytes(out: &mut Vec<u8>, encoded: &[u8]) {
    out.push(0x06);
    push_length(out, encoded.len());
    out.extend_from_slice(encoded);
}

#[cfg(test)]
fn push_null(out: &mut Vec<u8>) {
    out.push(0x05);
    out.push(0x00);
}

#[cfg(test)]
fn push_integer_be(out: &mut Vec<u8>, magnitude_be: &[u8]) {
    // DER INTEGER from an arbitrary-width big-endian magnitude (no
    // leading zeros expected). Used to encode values that don't fit a
    // u32 so the parser's range guard can be exercised. Adds a single
    // leading 0x00 when the top byte's MSB is set (keep it positive).
    let mut bytes = magnitude_be.to_vec();
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    out.push(0x02);
    push_length(out, bytes.len());
    out.extend_from_slice(&bytes);
}

#[cfg(test)]
fn push_integer_u32(out: &mut Vec<u8>, value: u32) {
    // Minimal DER INTEGER: drop leading zero bytes, add one if MSB
    // of top byte is set (to keep the value positive).
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    out.push(0x02);
    push_length(out, bytes.len());
    out.extend_from_slice(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_envelope() -> Vec<u8> {
        let kdf_salt = vec![0xAB; 20];
        let iv_inner = vec![0xCD; 14];
        let ciphertext = vec![0xEF; 32];
        encode_pbes2_envelope_for_tests(&kdf_salt, 10_000, 32, &iv_inner, &ciphertext)
    }

    /// Build a canonical envelope but with the iterationCount + keyLength
    /// INTEGERs supplied as raw big-endian magnitudes — lets a test
    /// encode values that exceed `u32` to exercise the range guard.
    fn envelope_with_int_magnitudes(iters_be: &[u8], keylen_be: &[u8]) -> Vec<u8> {
        let mut pbkdf2_params = Vec::new();
        push_octet_string(&mut pbkdf2_params, &[0xAB; 20]);
        push_integer_be(&mut pbkdf2_params, iters_be);
        push_integer_be(&mut pbkdf2_params, keylen_be);
        let mut prf_alg = Vec::new();
        push_oid_bytes(
            &mut prf_alg,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09],
        );
        push_null(&mut prf_alg);
        push_sequence(&mut pbkdf2_params, &prf_alg);
        let mut kdf_alg_id = Vec::new();
        push_oid_bytes(
            &mut kdf_alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C],
        );
        push_sequence(&mut kdf_alg_id, &pbkdf2_params);
        let mut enc_alg_id = Vec::new();
        push_oid_bytes(
            &mut enc_alg_id,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        );
        push_octet_string(&mut enc_alg_id, &[0xCD; 14]);
        let mut params = Vec::new();
        push_sequence(&mut params, &kdf_alg_id);
        push_sequence(&mut params, &enc_alg_id);
        let mut alg_id = Vec::new();
        push_oid_bytes(
            &mut alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D],
        );
        push_sequence(&mut alg_id, &params);
        let mut outer = Vec::new();
        push_sequence(&mut outer, &alg_id);
        push_octet_string(&mut outer, &[0xEF; 32]);
        let mut der = Vec::new();
        push_sequence(&mut der, &outer);
        der
    }

    #[test]
    fn parses_canonical_nss_envelope() {
        let der = canonical_envelope();
        let env = parse_pbes2_envelope(&der).expect("canonical envelope must parse");
        assert_eq!(env.kdf_salt, vec![0xAB; 20]);
        assert_eq!(env.kdf_iters, 10_000);
        assert_eq!(env.kdf_key_length, 32);
        assert_eq!(env.encryption_iv_inner, vec![0xCD; 14]);
        assert_eq!(env.ciphertext, vec![0xEF; 32]);
    }

    #[test]
    fn full_aes_cbc_iv_prepends_octet_string_header() {
        let env = parse_pbes2_envelope(&canonical_envelope()).unwrap();
        let iv = env.full_aes_cbc_iv();
        assert_eq!(iv[0], 0x04, "first byte must be OCTET STRING tag");
        assert_eq!(iv[1], 0x0e, "second byte must be length 14");
        assert_eq!(&iv[2..], &[0xCD; 14]);
        assert_eq!(iv.len(), 16, "full AES-CBC IV is 16 bytes");
    }

    #[test]
    fn rejects_truncated_outer_sequence() {
        let bytes = vec![0x30, 0x05];
        let err = parse_pbes2_envelope(&bytes).unwrap_err();
        // simple_asn1 surfaces this as either Asn1 (NotEnoughData) or
        // OuterNotSequence depending on its internal handling. Both
        // are valid rejection paths — we just care it doesn't accept
        // the truncated bytes.
        assert!(
            matches!(err, Pbes2Error::Asn1(_) | Pbes2Error::OuterNotSequence),
            "expected Asn1 or OuterNotSequence, got {err:?}",
        );
    }

    #[test]
    fn rejects_outer_arity_one_field() {
        // Outer SEQUENCE with just an OCTET STRING (no AlgId).
        let body = vec![0x04, 0x02, 0xAA, 0xBB];
        let mut outer = Vec::new();
        push_sequence(&mut outer, &body);
        let err = parse_pbes2_envelope(&outer).unwrap_err();
        match err {
            Pbes2Error::OuterArity { got } => assert_eq!(got, 1),
            // simple_asn1 may parse the single OCTET STRING as a
            // separate top-level block, yielding outer SEQUENCE of 0.
            other => assert!(
                matches!(
                    other,
                    Pbes2Error::OuterArity { .. } | Pbes2Error::OuterNotSequence
                ),
                "expected arity or not-sequence, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_wrong_outer_alg_id_oid() {
        // Build an envelope using the AES-256-CBC OID where the
        // outer AlgorithmIdentifier should hold the id-PBES2 OID.
        // Catches a class of confused-OID misuse.
        let mut kdf_alg_id = Vec::new();
        push_oid_bytes(
            &mut kdf_alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C],
        );
        push_sequence(&mut kdf_alg_id, &{
            let mut p = Vec::new();
            push_octet_string(&mut p, &[0xAA; 20]);
            push_integer_u32(&mut p, 1000);
            push_integer_u32(&mut p, 32);
            let mut prf = Vec::new();
            push_oid_bytes(&mut prf, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]);
            push_null(&mut prf);
            push_sequence(&mut p, &prf);
            p
        });
        let mut enc_alg = Vec::new();
        push_oid_bytes(
            &mut enc_alg,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        );
        push_octet_string(&mut enc_alg, &[0xBB; 14]);
        let mut params = Vec::new();
        push_sequence(&mut params, &kdf_alg_id);
        push_sequence(&mut params, &enc_alg);
        let mut alg_id = Vec::new();
        // WRONG: use AES-256-CBC OID instead of id-PBES2
        push_oid_bytes(
            &mut alg_id,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        );
        push_sequence(&mut alg_id, &params);
        let mut outer = Vec::new();
        push_sequence(&mut outer, &alg_id);
        push_octet_string(&mut outer, &[0xCC; 16]);
        let mut der = Vec::new();
        push_sequence(&mut der, &outer);

        let err = parse_pbes2_envelope(&der).unwrap_err();
        match err {
            Pbes2Error::UnsupportedAlgorithm { got } => {
                assert!(
                    got.contains("2.16.840.1.101.3.4.1.42"),
                    "must surface the wrong OID, got: {got}"
                );
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn rejects_iv_inner_with_wrong_length() {
        let kdf_salt = vec![0xAB; 20];
        let iv_inner_wrong = vec![0xCD; 8]; // 8 bytes — invalid for NSS
        let ciphertext = vec![0xEF; 16];
        // Build the envelope manually since the helper asserts on len.
        let mut pbkdf2_params = Vec::new();
        push_octet_string(&mut pbkdf2_params, &kdf_salt);
        push_integer_u32(&mut pbkdf2_params, 10_000);
        push_integer_u32(&mut pbkdf2_params, 32);
        let mut prf_alg = Vec::new();
        push_oid_bytes(
            &mut prf_alg,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09],
        );
        push_null(&mut prf_alg);
        push_sequence(&mut pbkdf2_params, &prf_alg);
        let mut kdf_alg_id = Vec::new();
        push_oid_bytes(
            &mut kdf_alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C],
        );
        push_sequence(&mut kdf_alg_id, &pbkdf2_params);
        let mut enc_alg_id = Vec::new();
        push_oid_bytes(
            &mut enc_alg_id,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        );
        push_octet_string(&mut enc_alg_id, &iv_inner_wrong);
        let mut params = Vec::new();
        push_sequence(&mut params, &kdf_alg_id);
        push_sequence(&mut params, &enc_alg_id);
        let mut alg_id = Vec::new();
        push_oid_bytes(
            &mut alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D],
        );
        push_sequence(&mut alg_id, &params);
        let mut outer = Vec::new();
        push_sequence(&mut outer, &alg_id);
        push_octet_string(&mut outer, &ciphertext);
        let mut der = Vec::new();
        push_sequence(&mut der, &outer);

        let err = parse_pbes2_envelope(&der).unwrap_err();
        match err {
            Pbes2Error::IvLenNotFourteen { got } => assert_eq!(got, 8),
            other => panic!("expected IvLenNotFourteen, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_prf_oid_sha1_instead_of_sha256() {
        // hmacWithSHA1 OID = 1.2.840.113549.2.7. NSS modern always
        // emits SHA256; reject SHA1 explicitly so a downgrade attack
        // (operator with a malicious key4.db) doesn't silently fall
        // back to weaker PBKDF2.
        let kdf_salt = vec![0xAB; 20];
        let iv_inner = vec![0xCD; 14];
        let ciphertext = vec![0xEF; 16];
        let mut pbkdf2_params = Vec::new();
        push_octet_string(&mut pbkdf2_params, &kdf_salt);
        push_integer_u32(&mut pbkdf2_params, 10_000);
        push_integer_u32(&mut pbkdf2_params, 32);
        let mut prf_alg = Vec::new();
        // hmacWithSHA1 OID
        push_oid_bytes(
            &mut prf_alg,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07],
        );
        push_null(&mut prf_alg);
        push_sequence(&mut pbkdf2_params, &prf_alg);
        let mut kdf_alg_id = Vec::new();
        push_oid_bytes(
            &mut kdf_alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C],
        );
        push_sequence(&mut kdf_alg_id, &pbkdf2_params);
        let mut enc_alg_id = Vec::new();
        push_oid_bytes(
            &mut enc_alg_id,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        );
        push_octet_string(&mut enc_alg_id, &iv_inner);
        let mut params = Vec::new();
        push_sequence(&mut params, &kdf_alg_id);
        push_sequence(&mut params, &enc_alg_id);
        let mut alg_id = Vec::new();
        push_oid_bytes(
            &mut alg_id,
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D],
        );
        push_sequence(&mut alg_id, &params);
        let mut outer = Vec::new();
        push_sequence(&mut outer, &alg_id);
        push_octet_string(&mut outer, &ciphertext);
        let mut der = Vec::new();
        push_sequence(&mut der, &outer);

        let err = parse_pbes2_envelope(&der).unwrap_err();
        match err {
            Pbes2Error::UnsupportedPrf { got } => {
                assert!(
                    got.contains("1.2.840.113549.2.7"),
                    "must surface the SHA1 OID, got: {got}"
                );
            }
            other => panic!("expected UnsupportedPrf, got {other:?}"),
        }
    }

    #[test]
    fn parses_minimal_iter_count() {
        // Edge case: iterationCount = 1 (legacy installs). Parser
        // must accept any positive u32.
        let der = encode_pbes2_envelope_for_tests(&[0xAA; 16], 1, 32, &[0xBB; 14], &[0xCC; 16]);
        let env = parse_pbes2_envelope(&der).unwrap();
        assert_eq!(env.kdf_iters, 1);
    }

    #[test]
    fn parses_large_iter_count() {
        // Modern NSS uses iters values in the 10k-100k range; ensure
        // the u32 conversion handles values that need multiple bytes.
        let der =
            encode_pbes2_envelope_for_tests(&[0xAA; 16], 100_000, 32, &[0xBB; 14], &[0xCC; 16]);
        let env = parse_pbes2_envelope(&der).unwrap();
        assert_eq!(env.kdf_iters, 100_000);
    }

    #[test]
    fn rejects_iter_count_above_u32_max() {
        // COR-24: 2^33 = 0x2_0000_0000 needs a 5-byte magnitude. The old
        // `.first()` took the low base-2^32 word (0) and accepted iters=0;
        // the range guard must reject it as OutOfRange, surfacing the real
        // value (8589934592) in the error.
        let der = envelope_with_int_magnitudes(&[0x02, 0x00, 0x00, 0x00, 0x00], &[32]);
        let err = parse_pbes2_envelope(&der).unwrap_err();
        match err {
            Pbes2Error::KdfItersOutOfRange { got } => {
                assert_eq!(got, "8589934592", "must surface the true value, got: {got}");
            }
            other => panic!("expected KdfItersOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn rejects_iter_count_low_word_truncation() {
        // 2^32 + 10000 = 0x1_0000_2710 — the low word is exactly 10000.
        // Must NOT silently parse as a plausible iters=10000.
        let der = envelope_with_int_magnitudes(&[0x01, 0x00, 0x00, 0x27, 0x10], &[32]);
        let err = parse_pbes2_envelope(&der).unwrap_err();
        assert!(
            matches!(err, Pbes2Error::KdfItersOutOfRange { .. }),
            "low-word collision must reject, got {err:?}"
        );
    }

    #[test]
    fn rejects_key_length_above_u32_max() {
        // Same overflow class on the keyLength field: valid iters but
        // keyLength = 2^33 must reject, not truncate to 0.
        let der = envelope_with_int_magnitudes(&[0x27, 0x10], &[0x02, 0x00, 0x00, 0x00, 0x00]);
        let err = parse_pbes2_envelope(&der).unwrap_err();
        assert!(
            matches!(err, Pbes2Error::KdfKeyLengthOutOfRange { .. }),
            "oversized keyLength must reject, got {err:?}"
        );
    }

    #[test]
    fn parses_iter_count_above_signed_max() {
        // Pin: a positive integer with MSB set in its high byte gets
        // a leading 0x00 in DER. The parser must still recover the
        // u32 value correctly.
        let der = encode_pbes2_envelope_for_tests(
            &[0xAA; 16],
            0x80_00_00_01,
            32,
            &[0xBB; 14],
            &[0xCC; 16],
        );
        let env = parse_pbes2_envelope(&der).unwrap();
        assert_eq!(env.kdf_iters, 0x80_00_00_01);
    }
}
