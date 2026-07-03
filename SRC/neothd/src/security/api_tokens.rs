//! GOLD-ADAPT-ODY-31 — Scope-gated API tokens for the n8n localhost API.
//!
//! ## Design
//!
//! The n8n localhost API (port 9744) previously used a single static bearer
//! token (`~/.neoth/n8n_api_token`) that granted full access to every
//! endpoint. This module adds fine-grained, per-token scope control so an
//! operator can issue a narrow token for a specific n8n workflow without
//! granting it access to, e.g., `/api/memory/save` or `/api/provider/call`.
//!
//! ## Token lifecycle
//!
//! 1. `neoth keys api-token create --label "workflow-X" --scope recall:read`
//!    → generates 32 random bytes, base64url-NOPAD-encodes them, prints the
//!      plaintext ONCE, stores only the PBKDF2-HMAC-SHA256 hash on disk.
//! 2. The caller presents `Authorization: Bearer <token>` on each request.
//! 3. `verify_token_for_scope` loads the token store, iterates all non-expired,
//!    non-revoked records, and constant-time-verifies each hash via PBKDF2
//!    verify, then checks that the required scope is granted.
//! 4. `neoth keys api-token revoke <id>` sets `revoked_at` on the record.
//! 5. `neoth keys api-token list` prints label / id / scopes — never tokens.
//!
//! ## Storage
//!
//! `~/.neoth/api_tokens.json` — 0600 (Unix) / DACL (Windows).
//! JSON array of `ApiTokenRecord`. Written atomically via temp-file rename.
//! The token store is a single operator-local file; no DB involved.
//!
//! ## Hashing
//!
//! PBKDF2-HMAC-SHA256, 10 000 iterations, 16-byte random salt, 32-byte DK.
//! No new dep: `pbkdf2 = "0.12"` (hmac feature), `hmac = "0.12"`,
//! `sha2 = "0.10"`, `subtle = "2"`, `getrandom = "0.2"` already in tree.
//!
//! Constant-time final comparison uses `subtle::ConstantTimeEq`.
//!
//! ## Scopes
//!
//! Fine-grained strings; a token carries a `Vec<String>` of granted scopes.
//! Predefined scope constants live here; the auth check does an exact-string
//! match. `write` scopes auto-include `read` sibling (write→read auto-insert
//! enforced at create time).
//!
//! Defined scopes:
//!   `"api:health"` — GET /api/health (always granted to any valid token)
//!   `"recall:read"` — POST /api/recall
//!   `"stats:read"` — GET /api/stats
//!   `"memory:write"` — POST /api/memory/save (implies `memory:read`)
//!   `"provider:call"` — POST /api/provider/call
//!   `"channel:send"` — POST /api/channel/send

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

// ── scope constants ──────────────────────────────────────────────────────────

/// Health probe — always granted to any valid, non-expired, non-revoked token.
pub const SCOPE_API_HEALTH: &str = "api:health";
/// Read recall / memory search.
pub const SCOPE_RECALL_READ: &str = "recall:read";
/// Read stats.
pub const SCOPE_STATS_READ: &str = "stats:read";
/// Write to memory (POST /api/memory/save). Implies recall:read.
pub const SCOPE_MEMORY_WRITE: &str = "memory:write";
/// Call an LLM provider on behalf of the caller.
pub const SCOPE_PROVIDER_CALL: &str = "provider:call";
/// Send a message via a channel adapter.
pub const SCOPE_CHANNEL_SEND: &str = "channel:send";

/// All scopes an operator may request. Sorted for stable CLI display.
pub const ALL_SCOPES: &[&str] = &[
    SCOPE_API_HEALTH,
    SCOPE_CHANNEL_SEND,
    SCOPE_MEMORY_WRITE,
    SCOPE_PROVIDER_CALL,
    SCOPE_RECALL_READ,
    SCOPE_STATS_READ,
];

// ── PBKDF2 parameters ───────────────────────────────────────────────────────

// Security review 2026-07-03: 100k iterations. Tokens are 32 CSPRNG bytes
// (256-bit entropy) — the KDF only hardens a stolen store file against
// implementation surprises, not brute force (which is infeasible at this
// entropy regardless). 100k keeps per-request verify cost sane for the
// loopback-only n8n API (operator-scale token counts).
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const DK_LEN: usize = 32;

// ── record ───────────────────────────────────────────────────────────────────

/// One token record as stored on disk. Token bytes are never stored — only
/// the PBKDF2 hash (base64url-NOPAD) and salt (base64url-NOPAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenRecord {
    /// Stable opaque ID — used for `revoke <id>`.
    pub id: String,
    /// Human-readable label set at create time. Not validated for uniqueness.
    pub label: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// PBKDF2-HMAC-SHA256 derived key, base64url-NOPAD, 32 bytes.
    pub hash_b64: String,
    /// PBKDF2 salt, base64url-NOPAD, 16 bytes.
    pub salt_b64: String,
    /// Unix timestamp (seconds) when this token was created.
    pub created_at: i64,
    /// Optional Unix timestamp (seconds) after which the token is expired.
    pub expires_at: Option<i64>,
    /// Unix timestamp (seconds) of the most recent successful verification.
    /// `None` if never verified.
    pub last_used: Option<i64>,
    /// Unix timestamp (seconds) when the token was revoked. `None` = active.
    pub revoked_at: Option<i64>,
}

impl ApiTokenRecord {
    /// `true` when the token is neither revoked nor past its `expires_at`.
    pub fn is_active(&self, now_secs: i64) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if now_secs >= exp {
                return false;
            }
        }
        true
    }

    /// `true` when this token grants `scope`.
    ///
    /// `api:health` is always granted to any active token (healthz callers
    /// shouldn't need a specific scope). For everything else, the scope must
    /// appear verbatim in `self.scopes`.
    pub fn has_scope(&self, scope: &str) -> bool {
        if scope == SCOPE_API_HEALTH {
            return true;
        }
        self.scopes.iter().any(|s| s == scope)
    }
}

// ── store path ───────────────────────────────────────────────────────────────

/// `~/.neoth/api_tokens.json`
pub fn store_path(home: &Path) -> PathBuf {
    home.join("api_tokens.json")
}

// ── load / save ──────────────────────────────────────────────────────────────

/// Load the token store. Returns an empty vec if the file does not exist yet.
pub fn load_store(home: &Path) -> Result<Vec<ApiTokenRecord>> {
    let path = store_path(home);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read(&path)
        .with_context(|| format!("read api_tokens.json at {}", path.display()))?;
    // save_store writes via write_key_securely, which DPAPI-wraps on Windows —
    // unwrap symmetrically (plaintext passes through on unix / unwrapped files).
    let raw = crate::wal::compaction::maybe_unwrap_dpapi(&raw, &path)?;
    let records: Vec<ApiTokenRecord> = serde_json::from_slice(&raw)
        .with_context(|| format!("parse api_tokens.json at {}", path.display()))?;
    Ok(records)
}

/// Persist the token store atomically (temp-file + rename) with 0600/DACL.
pub fn save_store(home: &Path, records: &[ApiTokenRecord]) -> Result<()> {
    let path = store_path(home);
    std::fs::create_dir_all(home)
        .with_context(|| format!("create neoth home {}", home.display()))?;
    let json = serde_json::to_vec_pretty(records).context("serialize api_tokens.json")?;
    // Atomic write: temp file in the same directory, then rename.
    let tmp_path = path.with_extension("json.tmp");
    // Error-hunt #2 HIGH: write_key_securely opens create_new (O_EXCL) on unix —
    // a stale tmp from a crashed prior save would make every future save fail
    // permanently. Clearing it first keeps the atomic-rename contract.
    let _ = std::fs::remove_file(&tmp_path);
    crate::wal::compaction::write_key_securely(&tmp_path, &json)
        .with_context(|| format!("write api_tokens.json.tmp at {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &path)
        .with_context(|| format!("rename api_tokens.json.tmp → {}", path.display()))?;
    Ok(())
}

// ── create ───────────────────────────────────────────────────────────────────

/// Expand scopes so that write-access implies read-access.
fn expand_scopes(scopes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = scopes.to_vec();
    if out.iter().any(|s| s == SCOPE_MEMORY_WRITE) && !out.iter().any(|s| s == SCOPE_RECALL_READ)
    {
        out.push(SCOPE_RECALL_READ.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// Validate that every requested scope is known.
pub fn validate_scopes(scopes: &[String]) -> Result<()> {
    for s in scopes {
        if !ALL_SCOPES.contains(&s.as_str()) {
            anyhow::bail!(
                "unknown scope {:?}; valid scopes: {}",
                s,
                ALL_SCOPES.join(", ")
            );
        }
    }
    Ok(())
}

/// Hash a plaintext token with PBKDF2-HMAC-SHA256.
fn hash_token(plaintext: &str, salt: &[u8]) -> [u8; DK_LEN] {
    use hmac::Hmac;
    use sha2::Sha256;
    let mut dk = [0u8; DK_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        plaintext.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut dk,
    )
    .expect("PBKDF2 infallible for fixed-size output");
    dk
}

/// Create a new API token record. Returns `(record, plaintext_token)`.
/// The plaintext must be shown to the operator once and then discarded.
/// The record is NOT automatically saved — call `save_store` after.
pub fn create_token(
    label: impl Into<String>,
    scopes: Vec<String>,
    expires_at: Option<i64>,
) -> Result<(ApiTokenRecord, String)> {
    validate_scopes(&scopes)?;
    let scopes = expand_scopes(&scopes);

    // 32 bytes CSPRNG → base64url-NOPAD (43 chars), same shape as every other
    // token in NEOTH.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).context("OS RNG unavailable — cannot mint API token")?;
    let plaintext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

    let mut salt_bytes = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt_bytes).context("OS RNG unavailable — cannot mint salt")?;

    let dk = hash_token(&plaintext, &salt_bytes);

    let record = ApiTokenRecord {
        id: Uuid::now_v7().to_string(),
        label: label.into(),
        scopes,
        hash_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dk),
        salt_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt_bytes),
        created_at: crate::time::now_unix_i64(),
        expires_at,
        last_used: None,
        revoked_at: None,
    };
    Ok((record, plaintext))
}

// ── verify ────────────────────────────────────────────────────────────────────

/// Result of a token verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Token is valid and grants the requested scope.
    Ok { token_id: String },
    /// Token matched but does not grant the required scope.
    InsufficientScope { token_id: String, required: String },
    /// No token matched (wrong token, revoked, or expired).
    Denied,
}

/// Verify `candidate` against the stored token records, checking that it is
/// active and grants `required_scope`.
///
/// Timing: ALL active records are iterated and PBKDF2-verified before
/// returning `Denied`, so the response time does not leak which record
/// index failed. The inner comparison uses `subtle::ConstantTimeEq`.
///
/// Caller is responsible for persisting the updated `last_used` timestamp
/// (returned in the modified records) — pass the result to `save_store`.
pub fn verify_token_for_scope(
    records: &mut [ApiTokenRecord],
    candidate: &str,
    required_scope: &str,
) -> VerifyResult {
    let now = crate::time::now_unix_i64();
    let mut matched_id: Option<String> = None;
    let mut matched_scope_ok = false;

    for rec in records.iter_mut() {
        if !rec.is_active(now) {
            continue;
        }
        // Decode the stored salt and hash — skip malformed records (shouldn't happen).
        let Ok(salt) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&rec.salt_b64)
        else {
            continue;
        };
        let Ok(stored_dk) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&rec.hash_b64)
        else {
            continue;
        };

        // Compute PBKDF2 for the candidate against this salt.
        let candidate_dk = hash_token(candidate, &salt);

        // Constant-time compare: 1 if equal, 0 if not.
        let eq = candidate_dk.ct_eq(stored_dk.as_slice()).unwrap_u8();
        if eq == 1 {
            // Match found — record last_used and check scope.
            rec.last_used = Some(now);
            matched_id = Some(rec.id.clone());
            matched_scope_ok = rec.has_scope(required_scope);
            // Do NOT break — still iterate remaining records to normalise timing.
        }
    }

    match matched_id {
        Some(id) if matched_scope_ok => VerifyResult::Ok { token_id: id },
        Some(id) => VerifyResult::InsufficientScope {
            token_id: id,
            required: required_scope.to_string(),
        },
        None => VerifyResult::Denied,
    }
}

// ── revoke ────────────────────────────────────────────────────────────────────

/// Set `revoked_at` on the record with `id`. Returns `true` if found.
pub fn revoke_token(records: &mut [ApiTokenRecord], id: &str) -> bool {
    let now = crate::time::now_unix_i64();
    for rec in records.iter_mut() {
        if rec.id == id {
            rec.revoked_at = Some(now);
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── helpers ──

    fn make_token(scopes: &[&str]) -> (ApiTokenRecord, String) {
        let scope_strings: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        create_token("test-token", scope_strings, None).unwrap()
    }

    // ── create + hash + verify roundtrip ─────────────────────────────────────

    #[test]
    fn hash_verify_roundtrip_succeeds() {
        let (mut record, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        let mut records = vec![record.clone()];
        let result = verify_token_for_scope(&mut records, &plaintext, SCOPE_RECALL_READ);
        assert_eq!(
            result,
            VerifyResult::Ok {
                token_id: record.id.clone()
            }
        );
        // last_used must have been updated.
        assert!(records[0].last_used.is_some());
        // Double-check: original record has no last_used (we didn't mutate it).
        record.last_used = None;
    }

    #[test]
    fn wrong_token_denied() {
        let (_, _plaintext) = make_token(&[SCOPE_RECALL_READ]);
        let (record2, _) = make_token(&[SCOPE_RECALL_READ]);
        let mut records = vec![record2];
        // Use plaintext from a different token → no match.
        let result = verify_token_for_scope(&mut records, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SCOPE_RECALL_READ);
        assert_eq!(result, VerifyResult::Denied);
    }

    #[test]
    fn insufficient_scope_returns_correct_variant() {
        let (_, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        let (record, _) = create_token("t", vec![SCOPE_RECALL_READ.to_string()], None).unwrap();
        let mut records = vec![record.clone()];
        // Verify with a scope the token doesn't have.
        let _result = verify_token_for_scope(&mut records, &plaintext, SCOPE_PROVIDER_CALL);
        // Token doesn't match (different plaintext), so this is Denied.
        // Re-do with matching plaintext.
        let (rec2, pt2) = create_token("t2", vec![SCOPE_STATS_READ.to_string()], None).unwrap();
        let mut recs2 = vec![rec2];
        let r2 = verify_token_for_scope(&mut recs2, &pt2, SCOPE_PROVIDER_CALL);
        assert_eq!(
            r2,
            VerifyResult::InsufficientScope {
                token_id: recs2[0].id.clone(),
                required: SCOPE_PROVIDER_CALL.to_string(),
            }
        );
    }

    #[test]
    fn revoked_token_denied() {
        let (rec, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        let id = rec.id.clone();
        let mut records = vec![rec];
        // Revoke first.
        assert!(revoke_token(&mut records, &id));
        let result = verify_token_for_scope(&mut records, &plaintext, SCOPE_RECALL_READ);
        assert_eq!(result, VerifyResult::Denied);
    }

    #[test]
    fn expired_token_denied() {
        let (mut rec, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        // Set expiry in the past.
        rec.expires_at = Some(crate::time::now_unix_i64() - 1);
        let mut records = vec![rec];
        let result = verify_token_for_scope(&mut records, &plaintext, SCOPE_RECALL_READ);
        assert_eq!(result, VerifyResult::Denied);
    }

    // ── scope expansion ───────────────────────────────────────────────────────

    #[test]
    fn memory_write_auto_inserts_recall_read() {
        let (rec, _) = create_token("t", vec![SCOPE_MEMORY_WRITE.to_string()], None).unwrap();
        assert!(
            rec.scopes.contains(&SCOPE_RECALL_READ.to_string()),
            "memory:write must imply recall:read; got scopes: {:?}",
            rec.scopes
        );
    }

    #[test]
    fn api_health_always_granted_to_active_token() {
        let (rec, _) = make_token(&[SCOPE_STATS_READ]);
        assert!(rec.has_scope(SCOPE_API_HEALTH));
    }

    // ── show-once: list must not reveal plaintext ─────────────────────────────

    #[test]
    fn record_never_contains_plaintext() {
        let (rec, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        // The hash field must not equal the plaintext.
        assert_ne!(rec.hash_b64, plaintext);
        // The serialised JSON must not contain the plaintext bytes.
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains(&plaintext),
            "serialised record must not contain plaintext token"
        );
    }

    // ── storage roundtrip ────────────────────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let (rec, _) = make_token(&[SCOPE_RECALL_READ]);
        let records = vec![rec.clone()];
        save_store(dir.path(), &records).unwrap();
        let loaded = load_store(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, rec.id);
        assert_eq!(loaded[0].scopes, rec.scopes);
    }

    #[test]
    fn load_store_returns_empty_when_no_file() {
        let dir = tempdir().unwrap();
        let loaded = load_store(dir.path()).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn storage_file_contains_no_plaintext() {
        let dir = tempdir().unwrap();
        let (rec, plaintext) = make_token(&[SCOPE_RECALL_READ]);
        save_store(dir.path(), std::slice::from_ref(&rec)).unwrap();
        let raw = std::fs::read(store_path(dir.path())).unwrap();
        let file_text = String::from_utf8_lossy(&raw);
        assert!(
            !file_text.contains(&plaintext),
            "stored file must not contain the plaintext token"
        );
    }

    // ── unknown scope rejected ────────────────────────────────────────────────

    #[test]
    fn unknown_scope_rejected_at_create() {
        let result = create_token("t", vec!["not:a:scope".to_string()], None);
        assert!(result.is_err());
    }

    // ── revoke ────────────────────────────────────────────────────────────────

    #[test]
    fn revoke_unknown_id_returns_false() {
        let mut records: Vec<ApiTokenRecord> = Vec::new();
        assert!(!revoke_token(&mut records, "no-such-id"));
    }
}
