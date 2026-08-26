//! GOLD-LF-P1-08 — externally signed receipt for complete offline grade imports.
//!
//! The mutable run directory never authenticates its own score inputs. An
//! operator-controlled evidence channel signs this compact canonical receipt;
//! report/show verify it with an explicit out-of-band Ed25519 public key.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::parity_harness::ImportedGradeFile;

pub const PARITY_IMPORT_RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const PARITY_IMPORT_RECEIPT_PURPOSE: &str = "neoth-recall-parity-import-receipt/v1";
pub const MAX_PARITY_IMPORT_RECEIPT_BYTES: usize = 64 * 1024;
pub const MAX_PARITY_IMPORT_SIGNATURE_BYTES: usize = 256;
pub const MAX_PARITY_IMPORT_PUBKEY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityImportReceiptBody {
    pub schema_version: u32,
    pub purpose: String,
    pub run_id: String,
    pub manifest_sha256: String,
    pub imports: Vec<ImportedGradeFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedParityImportReceipt {
    pub body: ParityImportReceiptBody,
    pub signature_b64: String,
}

impl SignedParityImportReceipt {
    /// Exact stable UTF-8 bytes covered by the detached Ed25519 signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.body).context("serialize canonical parity import receipt body")
    }

    /// Validate bounded syntax and canonical ordering before cryptographic use.
    pub fn validate_shape(&self) -> Result<()> {
        if self.body.schema_version != PARITY_IMPORT_RECEIPT_SCHEMA_VERSION {
            anyhow::bail!("unsupported parity import receipt schema version {}", self.body.schema_version);
        }
        if self.body.purpose != PARITY_IMPORT_RECEIPT_PURPOSE {
            anyhow::bail!("unexpected parity import receipt purpose");
        }
        validate_run_id(&self.body.run_id)?;
        validate_sha256(&self.body.manifest_sha256, "receipt manifest")?;
        if self.signature_b64.is_empty()
            || self.signature_b64.len() > MAX_PARITY_IMPORT_SIGNATURE_BYTES
            || self.signature_b64.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!("receipt signature must be a bounded non-whitespace base64 string");
        }
        if self.body.imports.is_empty() || self.body.imports.len() > 64 {
            anyhow::bail!("receipt imports must contain 1..=64 complete grader artifacts");
        }
        let mut prior: Option<&str> = None;
        for import in &self.body.imports {
            if import.grader_id.is_empty() || import.grader_id.len() > 64 || import.record_count == 0 {
                anyhow::bail!("receipt import has invalid grader identity or empty record count");
            }
            validate_sha256(&import.source_sha256, "receipt import")?;
            if prior.is_some_and(|previous| previous >= import.grader_id.as_str()) {
                anyhow::bail!("receipt imports must be strictly sorted by unique grader_id");
            }
            prior = Some(&import.grader_id);
        }
        Ok(())
    }

    pub fn verify(&self, expected_pubkey_b64: &str) -> Result<()> {
        self.validate_shape()?;
        if expected_pubkey_b64.is_empty()
            || expected_pubkey_b64.len() > MAX_PARITY_IMPORT_PUBKEY_BYTES
            || expected_pubkey_b64.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!("expected receipt public key must be a bounded non-whitespace base64 string");
        }
        crate::wal::signing::verify_b64(expected_pubkey_b64, &self.signature_b64, &self.canonical_bytes()?)
            .context("parity import receipt signature verification failed")
    }
}

pub fn parse_signed_parity_import_receipt(bytes: &[u8]) -> Result<SignedParityImportReceipt> {
    if bytes.len() > MAX_PARITY_IMPORT_RECEIPT_BYTES {
        anyhow::bail!("parity import receipt exceeds {MAX_PARITY_IMPORT_RECEIPT_BYTES} bytes");
    }
    let receipt: SignedParityImportReceipt = serde_json::from_slice(bytes)
        .context("parse signed parity import receipt")?;
    receipt.validate_shape()?;
    Ok(receipt)
}

pub(crate) fn validate_run_id(value: &str) -> Result<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        anyhow::bail!("run_id must be exactly 32 lowercase hexadecimal characters");
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        anyhow::bail!("{label} SHA256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imported(grader_id: &str) -> ImportedGradeFile {
        ImportedGradeFile {
            grader_id: grader_id.into(),
            source_sha256: "a".repeat(64),
            record_count: 200,
        }
    }

    fn signed() -> (SignedParityImportReceipt, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let mut receipt = SignedParityImportReceipt {
            body: ParityImportReceiptBody {
                schema_version: PARITY_IMPORT_RECEIPT_SCHEMA_VERSION,
                purpose: PARITY_IMPORT_RECEIPT_PURPOSE.into(),
                run_id: "b".repeat(32),
                manifest_sha256: "c".repeat(64),
                imports: vec![imported("grader-a")],
            },
            signature_b64: String::new(),
        };
        receipt.signature_b64 = crate::wal::signing::sign_b64(&key, &receipt.canonical_bytes().unwrap());
        (receipt, crate::wal::signing::pubkey_b64(&key))
    }

    #[test]
    fn signed_receipt_rejects_key_and_body_tampering() {
        let (receipt, key) = signed();
        receipt.verify(&key).unwrap();
        assert!(receipt.verify(&crate::wal::signing::pubkey_b64(
            &ed25519_dalek::SigningKey::from_bytes(&[20; 32]),
        )).is_err());
        let mut changed = receipt;
        changed.body.imports[0].source_sha256 = "d".repeat(64);
        assert!(changed.verify(&key).is_err());
    }

    #[test]
    fn receipt_requires_canonical_complete_body_shape() {
        let (mut receipt, _) = signed();
        receipt.body.purpose = "different-purpose".into();
        assert!(receipt.validate_shape().is_err());
        let (mut receipt, _) = signed();
        receipt.body.imports.push(imported("grader-a"));
        assert!(receipt.validate_shape().is_err());
    }
}
