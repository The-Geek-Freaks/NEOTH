//! Private, canonical content fingerprints for one isolated Update candidate.
//!
//! The JavaScript helper writes decrypted material only to the candidate's
//! hardened `/tmp` and emits a compact, domain-separated digest receipt.

use serde::Deserialize;

const SCRIPT: &str = include_str!("managed_update_verify.js");
const MAX_PROOF_BYTES: usize = 1024;
const READY_SCRIPT: &str = r#"'use strict';const http=require('node:http');let done=false;const end=ok=>{if(!done){done=true;process.exitCode=ok?0:23;}};const r=http.get({host:'127.0.0.1',port:5678,path:'/healthz',timeout:2000},s=>{let n=0;s.on('data',b=>{n+=b.length;if(n>1024){r.destroy();end(false);}});s.on('end',()=>end(s.statusCode===200));});r.on('timeout',()=>{r.destroy();end(false);});r.on('error',()=>end(false));"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateContentFingerprint {
    pub workflow_count: u32,
    pub credential_count: u32,
    pub content_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateContentProof {
    pub baseline: UpdateContentFingerprint,
    pub migrated: UpdateContentFingerprint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFingerprint {
    workflow_count: u32,
    credential_count: u32,
    content_sha256: String,
}

impl UpdateContentFingerprint {
    pub(crate) fn fingerprint_exact(&self, other: &Self) -> Result<(), &'static str> {
        if self != other {
            return Err("n8n_update_content_mismatch");
        }
        Ok(())
    }
}

impl UpdateContentProof {
    pub(crate) fn new(
        baseline: UpdateContentFingerprint,
        migrated: UpdateContentFingerprint,
    ) -> Result<Self, &'static str> {
        baseline.fingerprint_exact(&migrated)?;
        Ok(Self { baseline, migrated })
    }
}

pub(crate) fn decode_fingerprint(bytes: &[u8]) -> Result<UpdateContentFingerprint, &'static str> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err("n8n_update_content_proof_invalid");
    }
    let proof: WireFingerprint =
        serde_json::from_slice(bytes).map_err(|_| "n8n_update_content_proof_invalid")?;
    if !valid_sha256(&proof.content_sha256) {
        return Err("n8n_update_content_proof_invalid");
    }
    Ok(UpdateContentFingerprint {
        workflow_count: proof.workflow_count,
        credential_count: proof.credential_count,
        content_sha256: proof.content_sha256,
    })
}

/// Execute only after the caller observed the exact candidate identity and its
/// running state. This is intentionally a small adapter: custody and timeout
/// are provided by the managed runner, and no export bytes cross this boundary.
pub(crate) async fn fingerprint_exact(id: &str) -> Result<UpdateContentFingerprint, &'static str> {
    if !super::valid_container_id(id) {
        return Err("n8n_update_candidate_invalid_id");
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
        return Err("n8n_update_content_validation_failed");
    }
    decode_fingerprint(output.as_bytes())
}

/// Check the normal target server from inside its deliberately networkless
/// namespace. It sends no credential, follows no redirect, permits only the
/// fixed loopback health route, and the script itself has a two-second timeout.
pub(crate) async fn candidate_server_ready_exact(id: &str) -> Result<bool, &'static str> {
    if !super::valid_container_id(id) {
        return Err("n8n_update_candidate_invalid_id");
    }
    let (success, output, _) = super::docker(&[
        "docker".into(),
        "exec".into(),
        id.into(),
        "node".into(),
        "--no-warnings".into(),
        "-e".into(),
        READY_SCRIPT.into(),
    ])
    .await?;
    Ok(success && output.is_empty())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_fingerprints_are_required_for_update_content_proof() {
        let fingerprint = UpdateContentFingerprint {
            workflow_count: 2,
            credential_count: 1,
            content_sha256: "a".repeat(64),
        };
        assert!(UpdateContentProof::new(fingerprint.clone(), fingerprint).is_ok());
        assert!(
            UpdateContentProof::new(
                UpdateContentFingerprint {
                    workflow_count: 2,
                    credential_count: 1,
                    content_sha256: "a".repeat(64)
                },
                UpdateContentFingerprint {
                    workflow_count: 2,
                    credential_count: 1,
                    content_sha256: "b".repeat(64)
                },
            )
            .is_err()
        );
    }

    #[test]
    fn decoder_accepts_only_the_small_exact_public_receipt_shape() {
        let valid = format!(
            r#"{{"workflow_count":2,"credential_count":1,"content_sha256":"{}"}}"#,
            "a".repeat(64),
        );
        assert!(decode_fingerprint(valid.as_bytes()).is_ok());
        assert!(decode_fingerprint(br#"{"workflow_count":2,"credential_count":1,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","secret":"no"}"#).is_err());
        assert!(
            decode_fingerprint(
                br#"{"workflow_count":2,"credential_count":1,"content_sha256":"ABC"}"#
            )
            .is_err()
        );
    }
}
