//! C-04b Phase 2 chunk 1 (Session 27) — Firefox SECITEM envelope decode.
//!
//! Each `encryptedUsername` / `encryptedPassword` field in
//! `logins.json` is base64 of an ASN.1 BER `SEQUENCE` holding:
//!
//! ```text
//! SEQUENCE                            -- PKCS#7 EncryptedData
//!   OCTET STRING (key_id)             -- ref to key4.db row
//!   SEQUENCE                          -- AlgorithmIdentifier
//!     OID                             -- algorithm pick
//!     OCTET STRING (IV)               -- 16 bytes (AES) or 8 bytes (3DES)
//!   OCTET STRING (ciphertext)         -- PKCS#7-padded
//! ```
//!
//! Two algorithm OIDs are observed in the wild:
//!
//! - `2.16.840.1.101.3.4.1.42` — AES-256-CBC (modern Firefox /
//!   NSS 3.40+ key4.db). C-04b Phase 1 ships the matching CBC
//!   primitive.
//! - `1.2.840.113549.3.7` — DES-EDE3-CBC / 3DES (legacy
//!   key3.db installs that never migrated). Out of scope for
//!   Phase 2 chunk 1 — parser captures the OID + IV but the
//!   importer skips with a `LegacyAlgorithm` warning until a
//!   real 3DES primitive lands (Phase 3, if an operator
//!   surfaces a legacy install).
//!
//! Phase 2 chunk 2 (`key4.db` master-key extraction) consumes
//! the parsed envelope: hands `key_id` to the SQLite lookup,
//! feeds `iv` + `ciphertext` into the matching decrypt primitive.

use simple_asn1::{ASN1Block, from_der, oid};

/// Algorithm dispatched by the envelope's `AlgorithmIdentifier`
/// OID. The variants stay sealed via `#[non_exhaustive]` so a
/// future addition (e.g. AES-GCM if NSS ever moves) lands as a
/// breaking-but-explicit change rather than a silent OID accept.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirefoxAlgorithm {
    /// `2.16.840.1.101.3.4.1.42` — modern Firefox / NSS 3.40+.
    /// Decrypted via Phase 1's `decrypt_aes256_cbc_pkcs7`.
    Aes256Cbc,
    /// `1.2.840.113549.3.7` — legacy 3DES wrapping. Parser
    /// captures it but Phase 2 chunk 1 does not ship a decrypt
    /// primitive; the importer surfaces a warning.
    TripleDesCbc,
    /// Any other OID. Carries the decimal-dotted form so the
    /// operator-visible warning can name the unsupported algorithm
    /// without forcing a parser update.
    Unsupported(String),
}

impl FirefoxAlgorithm {
    /// Expected IV byte-length per algorithm. AES-CBC uses a
    /// 16-byte block; 3DES uses 8. Unsupported algorithms have
    /// no known length; the parser still accepts the OCTET
    /// STRING and surfaces the actual length on the envelope.
    pub fn expected_iv_len(&self) -> Option<usize> {
        match self {
            Self::Aes256Cbc => Some(16),
            Self::TripleDesCbc => Some(8),
            Self::Unsupported(_) => None,
        }
    }
}

/// Fully decoded Firefox SECITEM. `key_id` references the matching
/// row in `key4.db` (Phase 2 chunk 2 deliverable). `iv` is the
/// raw IV bytes; the algorithm dictates the expected length.
/// `ciphertext` is PKCS#7-padded — Phase 1's
/// `decrypt_aes256_cbc_pkcs7` strips the padding on success.
#[derive(Debug, Clone, PartialEq)]
pub struct FirefoxEnvelope {
    pub key_id: Vec<u8>,
    pub algorithm: FirefoxAlgorithm,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Errors that block envelope decoding. Operator sees these in
/// the wizard import-step warnings; the audit chain collapses
/// every variant into the same `Failed` outcome so the error
/// taxonomy never reveals which structural branch fired (no
/// padding-oracle-adjacent side channels through error
/// differentiation).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("base64 decode failed: {0}")]
    Base64(String),
    #[error("ASN.1 decode failed: {0}")]
    Asn1(String),
    #[error("envelope outer block must be SEQUENCE")]
    OuterNotSequence,
    #[error("envelope SEQUENCE must hold exactly 3 fields, got {got}")]
    OuterArity { got: usize },
    #[error("envelope field {field} must be OCTET STRING")]
    FieldNotOctetString { field: &'static str },
    #[error("AlgorithmIdentifier must be SEQUENCE")]
    AlgIdNotSequence,
    #[error("AlgorithmIdentifier SEQUENCE must hold exactly 2 fields, got {got}")]
    AlgIdArity { got: usize },
    #[error("AlgorithmIdentifier first field must be OID")]
    AlgIdNotOid,
    #[error("AlgorithmIdentifier second field must be OCTET STRING (IV)")]
    AlgIdIvNotOctetString,
    #[error(
        "IV length mismatch for algorithm: got {got_len}, expected {expected_len} for {algo:?}"
    )]
    IvLenMismatch {
        got_len: usize,
        expected_len: usize,
        algo: FirefoxAlgorithm,
    },
}

/// Parse a Firefox SECITEM envelope from its base64 wire form
/// (the exact bytes that land in `logins.json::encryptedUsername`
/// / `encryptedPassword`).
///
/// Strict shape enforcement: any deviation from the canonical
/// SEQUENCE { OCTET STRING, SEQUENCE { OID, OCTET STRING },
/// OCTET STRING } surfaces as `EnvelopeError::*` rather than
/// being silently accepted. Errors carry operator-readable
/// detail but the importer must collapse the taxonomy before
/// it reaches the audit chain.
pub fn parse_firefox_envelope(b64: &str) -> Result<FirefoxEnvelope, EnvelopeError> {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| EnvelopeError::Base64(e.to_string()))?;
    let blocks = from_der(&der).map_err(|e| EnvelopeError::Asn1(e.to_string()))?;
    if blocks.is_empty() {
        return Err(EnvelopeError::OuterNotSequence);
    }
    let outer = match &blocks[0] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(EnvelopeError::OuterNotSequence),
    };
    if outer.len() != 3 {
        return Err(EnvelopeError::OuterArity { got: outer.len() });
    }
    let key_id = match &outer[0] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => {
            return Err(EnvelopeError::FieldNotOctetString {
                field: "key_id (field 0)",
            });
        }
    };
    let alg_id_inner = match &outer[1] {
        ASN1Block::Sequence(_, inner) => inner,
        _ => return Err(EnvelopeError::AlgIdNotSequence),
    };
    if alg_id_inner.len() != 2 {
        return Err(EnvelopeError::AlgIdArity {
            got: alg_id_inner.len(),
        });
    }
    let oid_block = match &alg_id_inner[0] {
        ASN1Block::ObjectIdentifier(_, oid) => oid,
        _ => return Err(EnvelopeError::AlgIdNotOid),
    };
    let algorithm = oid_to_algorithm(oid_block);
    let iv = match &alg_id_inner[1] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => return Err(EnvelopeError::AlgIdIvNotOctetString),
    };
    if let Some(expected_len) = algorithm.expected_iv_len() {
        if iv.len() != expected_len {
            return Err(EnvelopeError::IvLenMismatch {
                got_len: iv.len(),
                expected_len,
                algo: algorithm,
            });
        }
    }
    let ciphertext = match &outer[2] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => {
            return Err(EnvelopeError::FieldNotOctetString {
                field: "ciphertext (field 2)",
            });
        }
    };
    Ok(FirefoxEnvelope {
        key_id,
        algorithm,
        iv,
        ciphertext,
    })
}

fn oid_to_algorithm(oid: &simple_asn1::OID) -> FirefoxAlgorithm {
    let aes_256_cbc = oid!(2, 16, 840, 1, 101, 3, 4, 1, 42);
    let triple_des_cbc = oid!(1, 2, 840, 113549, 3, 7);
    if oid == aes_256_cbc {
        FirefoxAlgorithm::Aes256Cbc
    } else if oid == triple_des_cbc {
        FirefoxAlgorithm::TripleDesCbc
    } else {
        FirefoxAlgorithm::Unsupported(format_oid_dotted(oid))
    }
}

/// Render a parsed OID as its decimal-dotted form (e.g.
/// `"2.16.840.1.101.3.4.1.42"`) for operator-visible error
/// strings. Uses `as_vec::<u128>()` which covers every real OID
/// arc (no observed crypto OID has arcs larger than u32, let
/// alone u128); on the off chance an arc exceeds u128, falls
/// back to the simple_asn1 Debug formatter so the operator at
/// least sees the BigUint debug shape rather than an empty
/// string.
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Hand-rolled BER bytes for a canonical Firefox SECITEM
    /// envelope. Used as the fixture for the positive-case test.
    /// Each byte is annotated so a future maintainer can verify
    /// the structure without re-running through an ASN.1 dumper.
    fn aes_256_cbc_envelope_der() -> Vec<u8> {
        let mut out = Vec::new();
        // ── outer SEQUENCE ─────────────────────────────────────────
        // Tag 0x30 + length (computed at end with backpatch).
        out.push(0x30);
        let outer_len_pos = out.len();
        out.push(0); // placeholder

        // ── key_id OCTET STRING (16 bytes) ────────────────────────
        out.push(0x04); // OCTET STRING tag
        out.push(0x10); // length = 16
        out.extend_from_slice(&[0xF8; 16]); // 16x 0xF8 (sentinel)

        // ── AlgorithmIdentifier SEQUENCE ──────────────────────────
        out.push(0x30); // SEQUENCE tag
        let alg_len_pos = out.len();
        out.push(0); // placeholder

        // ── OID 2.16.840.1.101.3.4.1.42 (AES-256-CBC) ─────────────
        out.push(0x06); // OID tag
        out.push(0x09); // length = 9
        out.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]);

        // ── IV OCTET STRING (16 bytes) ────────────────────────────
        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xAA; 16]);

        // Backpatch alg_id length (everything since alg_len_pos+1).
        let alg_len = out.len() - alg_len_pos - 1;
        out[alg_len_pos] = alg_len as u8;

        // ── ciphertext OCTET STRING (32 bytes — 2 AES blocks) ─────
        out.push(0x04);
        out.push(0x20);
        out.extend(0u8..32u8);

        // Backpatch outer length.
        let outer_len = out.len() - outer_len_pos - 1;
        out[outer_len_pos] = outer_len as u8;
        out
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn parses_canonical_aes_256_cbc_envelope() {
        let der = aes_256_cbc_envelope_der();
        let env = parse_firefox_envelope(&b64(&der)).expect("canonical envelope must parse");
        assert_eq!(env.algorithm, FirefoxAlgorithm::Aes256Cbc);
        assert_eq!(env.key_id, vec![0xF8; 16]);
        assert_eq!(env.iv, vec![0xAA; 16]);
        assert_eq!(env.ciphertext.len(), 32);
        // Ciphertext is the 0..32 byte range — drift guard pins the
        // outer SEQUENCE indexing (off-by-one would land 1..33).
        assert_eq!(env.ciphertext, (0u8..32u8).collect::<Vec<u8>>());
    }

    #[test]
    fn parses_3des_envelope_as_triple_des_variant() {
        // Same structure as canonical AES envelope, but with the
        // 3DES OID and an 8-byte IV. Hand-rolled to keep parity
        // with the modern fixture.
        let mut out = Vec::new();
        out.push(0x30); // outer SEQUENCE
        let outer_len_pos = out.len();
        out.push(0);

        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xF8; 16]); // key_id

        out.push(0x30);
        let alg_len_pos = out.len();
        out.push(0);

        // OID 1.2.840.113549.3.7 (DES-EDE3-CBC):
        //   1.2 → 0x2A; 840 → 0x86 0x48;
        //   113549 → 0x86 0xF7 0x0D;
        //   3 → 0x03; 7 → 0x07
        out.push(0x06);
        out.push(0x08);
        out.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07]);

        // IV (8 bytes — 3DES block size)
        out.push(0x04);
        out.push(0x08);
        out.extend_from_slice(&[0xBB; 8]);

        let alg_len = out.len() - alg_len_pos - 1;
        out[alg_len_pos] = alg_len as u8;

        // ciphertext
        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xCC; 16]);

        let outer_len = out.len() - outer_len_pos - 1;
        out[outer_len_pos] = outer_len as u8;

        let env = parse_firefox_envelope(&b64(&out)).expect("3des envelope must parse");
        assert_eq!(env.algorithm, FirefoxAlgorithm::TripleDesCbc);
        assert_eq!(env.iv.len(), 8, "3DES IV must be exactly 8 bytes");
    }

    #[test]
    fn rejects_iv_with_wrong_length_for_algorithm() {
        // Build an envelope with the AES-256-CBC OID but an 8-byte
        // IV (which would be valid for 3DES but invalid for AES).
        // This catches a class of malicious envelopes that try to
        // smuggle a 3DES-shaped IV into the AES path.
        let mut out = Vec::new();
        out.push(0x30);
        let outer_len_pos = out.len();
        out.push(0);

        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xF8; 16]);

        out.push(0x30);
        let alg_len_pos = out.len();
        out.push(0);

        out.push(0x06);
        out.push(0x09);
        out.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]);

        out.push(0x04);
        out.push(0x08); // length 8 — WRONG for AES-256-CBC
        out.extend_from_slice(&[0xAA; 8]);

        let alg_len = out.len() - alg_len_pos - 1;
        out[alg_len_pos] = alg_len as u8;

        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xCC; 16]);

        let outer_len = out.len() - outer_len_pos - 1;
        out[outer_len_pos] = outer_len as u8;

        let err = parse_firefox_envelope(&b64(&out)).unwrap_err();
        match err {
            EnvelopeError::IvLenMismatch {
                got_len,
                expected_len,
                algo,
            } => {
                assert_eq!(got_len, 8);
                assert_eq!(expected_len, 16);
                assert_eq!(algo, FirefoxAlgorithm::Aes256Cbc);
            }
            other => panic!("expected IvLenMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_algorithm_oid_without_iv_check() {
        // OID 1.3.6.1.4.1.99999.1 — arbitrary unassigned. Parser
        // accepts the structure (no IV-length check) so the
        // importer can surface "unsupported algorithm" cleanly.
        let mut out = Vec::new();
        out.push(0x30);
        let outer_len_pos = out.len();
        out.push(0);

        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xF8; 16]);

        out.push(0x30);
        let alg_len_pos = out.len();
        out.push(0);

        // OID 1.3.6.1.4.1.99999.1:
        //   1.3 → 0x2B; 6 → 0x06; 1 → 0x01; 4 → 0x04; 1 → 0x01;
        //   99999 → base-128 [6, 13, 31] with high-bit-set on
        //   non-final bytes → [0x86, 0x8D, 0x1F];
        //   trailing 1 → 0x01.
        out.push(0x06);
        out.push(0x09);
        out.extend_from_slice(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01]);

        // IV of arbitrary length — must NOT be rejected for
        // Unsupported variant.
        out.push(0x04);
        out.push(0x05);
        out.extend_from_slice(&[0xAA; 5]);

        let alg_len = out.len() - alg_len_pos - 1;
        out[alg_len_pos] = alg_len as u8;

        out.push(0x04);
        out.push(0x10);
        out.extend_from_slice(&[0xCC; 16]);

        let outer_len = out.len() - outer_len_pos - 1;
        out[outer_len_pos] = outer_len as u8;

        let env = parse_firefox_envelope(&b64(&out)).expect("unsupported algo must parse");
        match env.algorithm {
            FirefoxAlgorithm::Unsupported(s) => {
                assert!(
                    s.contains("99999"),
                    "dotted form must surface the unknown arc, got: {s}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert_eq!(env.iv.len(), 5, "unsupported variant skips IV-len check");
    }

    #[test]
    fn rejects_truncated_outer_sequence() {
        let mut out = Vec::new();
        out.push(0x30); // SEQUENCE tag
        out.push(0x05); // claims 5 bytes but provides 0
        let err = parse_firefox_envelope(&b64(&out)).unwrap_err();
        // Accept either Asn1 (simple_asn1 raises NotEnoughData) or
        // OuterNotSequence (if the lib returns an empty Vec instead).
        // Both are valid rejection paths; we care that the parser
        // doesn't accept the truncation as a 0-arity SEQUENCE.
        assert!(
            matches!(
                err,
                EnvelopeError::Asn1(_) | EnvelopeError::OuterNotSequence
            ),
            "expected Asn1 or OuterNotSequence, got {err:?}",
        );
    }

    #[test]
    fn rejects_outer_arity_mismatch() {
        // SEQUENCE containing only ONE OCTET STRING (no AlgId, no
        // ciphertext). Parser must surface the arity error not panic.
        let mut out = Vec::new();
        out.push(0x30);
        let outer_len_pos = out.len();
        out.push(0);
        out.push(0x04);
        out.push(0x04);
        out.extend_from_slice(&[0xF8; 4]);
        let outer_len = out.len() - outer_len_pos - 1;
        out[outer_len_pos] = outer_len as u8;

        let err = parse_firefox_envelope(&b64(&out)).unwrap_err();
        match err {
            EnvelopeError::OuterArity { got } => assert_eq!(got, 1),
            other => panic!("expected OuterArity, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = parse_firefox_envelope("!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, EnvelopeError::Base64(_)));
    }

    #[test]
    fn rejects_outer_not_sequence() {
        // Top-level OCTET STRING — caller passed a SECITEM-inner
        // field by mistake, not the whole envelope.
        let bytes = vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let err = parse_firefox_envelope(&b64(&bytes)).unwrap_err();
        assert_eq!(err, EnvelopeError::OuterNotSequence);
    }

    #[test]
    fn expected_iv_len_matrix_pinned() {
        assert_eq!(FirefoxAlgorithm::Aes256Cbc.expected_iv_len(), Some(16));
        assert_eq!(FirefoxAlgorithm::TripleDesCbc.expected_iv_len(), Some(8));
        assert_eq!(
            FirefoxAlgorithm::Unsupported("x".into()).expected_iv_len(),
            None,
            "Unsupported variant must not claim an IV length — the parser \
             accepts arbitrary IV bytes so the importer can surface the OID \
             without forcing a parser update"
        );
    }
}
