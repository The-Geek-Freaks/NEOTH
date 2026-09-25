//! Fixed offline validation inside an already observed restore candidate.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::managed_restore_candidate::RestoreCandidateContentReceipt;

const SCRIPT: &str = include_str!("managed_restore_verify.js");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentProof {
    workflow_count: u32,
    credential_count: u32,
    credential_decryption_proven: bool,
    evidence_sha256: String,
}

fn decode_proof(bytes: &[u8]) -> Result<RestoreCandidateContentReceipt, &'static str> {
    if bytes.len() > 1024 {
        return Err("n8n_restore_content_proof_invalid");
    }
    let proof: ContentProof =
        serde_json::from_slice(bytes).map_err(|_| "n8n_restore_content_proof_invalid")?;
    if proof.credential_decryption_proven != (proof.credential_count > 0) {
        return Err("n8n_restore_content_proof_invalid");
    }
    let canonical = format!(
        "{{\"workflow_count\":{},\"credential_count\":{},\"credential_decryption_proven\":{}}}",
        proof.workflow_count, proof.credential_count, proof.credential_decryption_proven,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"neoth-n8n-restore-content-v1\0");
    hasher.update(canonical.as_bytes());
    if hex::encode(hasher.finalize()) != proof.evidence_sha256 {
        return Err("n8n_restore_content_proof_invalid");
    }
    Ok(RestoreCandidateContentReceipt {
        workflow_count: proof.workflow_count,
        credential_count: proof.credential_count,
        credential_decryption_proven: proof.credential_decryption_proven,
        evidence_sha256: proof.evidence_sha256,
    })
}

pub(super) fn valid_receipt(receipt: &RestoreCandidateContentReceipt) -> bool {
    serde_json::to_vec(receipt)
        .ok()
        .and_then(|bytes| decode_proof(&bytes).ok())
        .is_some()
}

pub(super) async fn validate_content_exact(
    id: &str,
) -> Result<RestoreCandidateContentReceipt, &'static str> {
    if !super::valid_container_id(id) {
        return Err("n8n_restore_candidate_invalid_id");
    }
    let (success, output, _) = super::docker(&[
        "docker".into(),
        "exec".into(),
        id.into(),
        "node".into(),
        "--no-warnings".into(),
        "-e".into(),
        SCRIPT.into(),
    ])
    .await?;
    if !success {
        return Err("n8n_restore_content_validation_failed");
    }
    decode_proof(output.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(workflows: u32, credentials: u32, decrypted: bool) -> Vec<u8> {
        let canonical = format!(
            "{{\"workflow_count\":{workflows},\"credential_count\":{credentials},\"credential_decryption_proven\":{decrypted}}}",
        );
        let mut hash = Sha256::new();
        hash.update(b"neoth-n8n-restore-content-v1\0");
        hash.update(canonical.as_bytes());
        let digest = hex::encode(hash.finalize());
        let mut value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        value["evidence_sha256"] = digest.into();
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn content_proof_distinguishes_empty_credentials_from_verified_decryption() {
        let empty = decode_proof(&proof(0, 0, false)).unwrap();
        assert!(!empty.credential_decryption_proven);
        assert_eq!(empty.credential_count, 0);
        let nonempty = decode_proof(&proof(13, 1, true)).unwrap();
        assert!(nonempty.credential_decryption_proven);
        assert_eq!(nonempty.workflow_count, 13);
        assert!(decode_proof(&proof(13, 1, false)).is_err());
        assert!(decode_proof(&proof(13, 0, true)).is_err());
    }

    #[test]
    fn content_proof_rejects_modified_counts_and_unexpected_payloads() {
        let mut value: serde_json::Value = serde_json::from_slice(&proof(13, 1, true)).unwrap();
        value["workflow_count"] = 14.into();
        assert!(decode_proof(&serde_json::to_vec(&value).unwrap()).is_err());
        value["workflow_count"] = 13.into();
        value["data"] = "must never be a proof field".into();
        assert!(decode_proof(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decode_proof(&[b' '; 1025]).is_err());
    }
}
