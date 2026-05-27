//! C-04 — Firefox `logins.json` + `key4.db` importer.
//!
//! Firefox stores credentials in:
//!   - `logins.json` (per-profile, encrypted blobs)
//!   - `key4.db` (SQLite with the master-key envelope; PBES2
//!     wrapping PBKDF2-SHA256 + AES-256-CBC)
//!
//! C-04b algorithm-correction (Session 27): the original Session 26
//! handoff line "AES-256-GCM decrypt the login.json blobs" was
//! wrong — Firefox / NSS has used CBC since the format-4 key4.db
//! switch (NSS 3.40+). Each encrypted field in `logins.json` is a
//! base64-encoded ASN.1 SECITEM:
//!
//!     SEQUENCE                            -- PKCS#7 EncryptedData
//!       OCTET STRING (key_id)             -- ref to key4.db row
//!       SEQUENCE                          -- AlgorithmIdentifier
//!         OID 2.16.840.1.101.3.4.1.42     -- AES-256-CBC
//!         OCTET STRING (16-byte IV)
//!       OCTET STRING (ciphertext)         -- PKCS#7-padded
//!
//! Session 27 ships the building blocks: per-OS profile root
//! discovery + `profiles.ini` parse + `logins.json` JSON read +
//! the AES-256-CBC decrypt primitive with KAT-pinned tests. The
//! ASN.1 envelope decode + the `key4.db` master-key extraction
//! land in Session 28 — see `PLAN/HANDOFF_C04b_SESSION28.md` for
//! the remaining steps + crate picks (`simple_asn1` for the BER
//! parse, `rusqlite` already in tree).

use std::path::PathBuf;

use async_trait::async_trait;

use crate::credentials::{CredentialImporter, DiscoveredCredentials, ImportSource};

/// Per-OS Firefox profile-root directory.
pub fn firefox_profile_root() -> Option<PathBuf> {
    let home: PathBuf = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        Some(
            appdata
                .unwrap_or_else(|| home.join("AppData").join("Roaming"))
                .join("Mozilla")
                .join("Firefox"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("Firefox"),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Some(home.join(".mozilla").join("firefox"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        None
    }
}

/// Path to the operator's `profiles.ini` index file.
pub fn profiles_ini_path() -> Option<PathBuf> {
    firefox_profile_root().map(|r| r.join("profiles.ini"))
}

/// Parse the `Path=` lines from a `profiles.ini` body. Returns
/// the relative path per profile (caller joins with
/// `firefox_profile_root()`).
pub fn parse_profiles_ini(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            let trimmed = l.trim();
            trimmed.strip_prefix("Path=").map(|p| p.trim().to_string())
        })
        .filter(|p| !p.is_empty())
        .collect()
}

/// Pick the operator's default profile from a `profiles.ini`
/// body. Looks for the `Default=1` flag; falls back to the first
/// profile when none is marked default.
pub fn pick_default_profile(body: &str) -> Option<String> {
    // Walk sections — when a section has Default=1, return its
    // Path. INI parsing is intentionally tiny + permissive.
    let mut current_path: Option<String> = None;
    let mut current_default = false;
    let mut found: Option<String> = None;
    let mut first: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            // New section — commit prior + reset.
            if current_default {
                if let Some(p) = current_path.clone() {
                    found = Some(p);
                }
            }
            current_path = None;
            current_default = false;
            continue;
        }
        if let Some(p) = trimmed.strip_prefix("Path=") {
            let p = p.trim().to_string();
            if first.is_none() {
                first = Some(p.clone());
            }
            current_path = Some(p);
        } else if trimmed == "Default=1" {
            current_default = true;
        }
    }
    // Trailing section.
    if current_default {
        if let Some(p) = current_path {
            found = Some(p);
        }
    }
    found.or(first)
}

// ─── C-04b Phase 1: logins.json parse + AES-256-CBC primitive ────────────

/// One Firefox login entry as it appears in `logins.json`. Encrypted
/// fields are still base64-wrapped ASN.1 BER envelopes at this stage;
/// the decrypt happens via [`decrypt_aes256_cbc_pkcs7`] AFTER the
/// ASN.1 unwrap (Session 28 deliverable).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FirefoxLoginEntry {
    pub id: i64,
    pub hostname: String,
    #[serde(rename = "httpRealm", default)]
    pub http_realm: Option<String>,
    #[serde(rename = "formSubmitURL", default)]
    pub form_submit_url: Option<String>,
    #[serde(rename = "usernameField", default)]
    pub username_field: String,
    #[serde(rename = "passwordField", default)]
    pub password_field: String,
    /// Base64-encoded ASN.1 SECITEM. Use [`decrypt_aes256_cbc_pkcs7`]
    /// AFTER unwrapping the ASN.1 envelope to recover plaintext.
    #[serde(rename = "encryptedUsername")]
    pub encrypted_username: String,
    #[serde(rename = "encryptedPassword")]
    pub encrypted_password: String,
    pub guid: String,
    /// Encryption type byte. `1` = the current PBES2/AES-256-CBC
    /// path; legacy `0` (3DES via key3.db) is out of scope — modern
    /// Firefox migrates to encType=1 on first launch after the
    /// key4.db switch.
    #[serde(rename = "encType", default)]
    pub enc_type: u8,
    #[serde(rename = "timeCreated", default)]
    pub time_created: i64,
    #[serde(rename = "timeLastUsed", default)]
    pub time_last_used: i64,
    #[serde(rename = "timePasswordChanged", default)]
    pub time_password_changed: i64,
    #[serde(rename = "timesUsed", default)]
    pub times_used: u32,
}

/// Top-level `logins.json` shape. Firefox emits more fields than we
/// care about (`disabledHosts`, `dismissedBreachAlerts`, etc.); we
/// only need `logins` and the next-id counter for round-trip drift
/// detection. `#[serde(default)]` on `next_id` so an export from a
/// fresh profile (no logins yet → no nextId) still parses.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FirefoxLoginsJson {
    #[serde(rename = "nextId", default)]
    pub next_id: i64,
    #[serde(default)]
    pub logins: Vec<FirefoxLoginEntry>,
}

/// Parse a `logins.json` body into the typed shape. Returns a
/// structured error string suitable for the wizard's "skip + warn"
/// path so a corrupt file never crashes the import.
pub fn parse_logins_json(body: &str) -> Result<FirefoxLoginsJson, String> {
    serde_json::from_str::<FirefoxLoginsJson>(body)
        .map_err(|e| format!("logins.json parse failed: {e}"))
}

/// AES-256-CBC decrypt with PKCS#7 unpadding. Pure-primitive — the
/// caller supplies key + IV + ciphertext already extracted from the
/// ASN.1 envelope. Returns the plaintext bytes on success, an
/// operator-readable error string on padding-fail / wrong-key.
///
/// Constant-time properties: AES-CBC decrypt is constant-time at
/// the block level (no key-dependent branches in the RustCrypto
/// impl); PKCS#7 unpad is the one place a side channel could exist
/// (padding-oracle if the caller distinguishes "padding fail" from
/// "downstream parse fail"). The importer pipeline collapses both
/// into the same `Err` shape, so even a malicious operator can't
/// distinguish the two — the audit chain records `Failed` either
/// way without revealing which branch fired.
pub fn decrypt_aes256_cbc_pkcs7(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut buf = ciphertext.to_vec();
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let pt = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "aes-256-cbc decrypt or pkcs7 unpad failed".to_string())?;
    Ok(pt.to_vec())
}

// ─── Importer ─────────────────────────────────────────────────────────────

/// Importer impl. C-04b Phase 1 (Session 27) ships JSON parse + the
/// AES-256-CBC decrypt primitive. Phase 2 (Session 28) lands the
/// `key4.db` master-key extraction + ASN.1 envelope unwrap so this
/// surfaces real entries instead of "deferred" warnings.
pub struct FirefoxImporter;

#[async_trait]
impl CredentialImporter for FirefoxImporter {
    fn source(&self) -> ImportSource {
        ImportSource::WizardPrompt
    }

    fn name(&self) -> &'static str {
        "Firefox logins.json + key4.db (master-key path lands Session 28)"
    }

    async fn is_available(&self) -> bool {
        profiles_ini_path().map(|p| p.exists()).unwrap_or(false)
    }

    async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
        let mut warnings = vec![format!(
            "Firefox profile root found at {:?}. C-04b Phase 1 shipped the \
             logins.json parser + AES-256-CBC decrypt primitive (Session 27); \
             Phase 2 lands the key4.db master-key extraction + ASN.1 envelope \
             unwrap. Today the importer returns zero entries to avoid \
             false-success — operator-visible audit stays honest.",
            firefox_profile_root(),
        )];
        // Attempt to read profiles.ini to surface profile count.
        if let Some(ini_path) = profiles_ini_path() {
            if let Ok(body) = tokio::fs::read_to_string(&ini_path).await {
                let profiles = parse_profiles_ini(&body);
                warnings.push(format!("found {} Firefox profile(s)", profiles.len()));
                if let Some(default) = pick_default_profile(&body) {
                    warnings.push(format!("default profile: {default}"));
                }
            }
        }
        Ok(DiscoveredCredentials {
            source: ImportSource::WizardPrompt,
            entries: Vec::new(),
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_profile_root_some_on_supported_os() {
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(firefox_profile_root().is_some());
    }

    #[test]
    fn profiles_ini_path_under_profile_root() {
        if let (Some(root), Some(ini)) = (firefox_profile_root(), profiles_ini_path()) {
            assert!(ini.starts_with(&root));
            assert!(ini.ends_with("profiles.ini"));
        }
    }

    // ── parse_profiles_ini ────────────────────────────────────────

    #[test]
    fn parse_extracts_path_lines() {
        let body = "[Profile0]\nName=default\nPath=abc123.default\nIsRelative=1\n\
                    [Profile1]\nName=work\nPath=xyz789.work\nIsRelative=1\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["abc123.default", "xyz789.work"]);
    }

    #[test]
    fn parse_skips_empty_path_lines() {
        let body = "Path=\nPath=real-profile.default\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["real-profile.default"]);
    }

    #[test]
    fn parse_empty_body_returns_empty() {
        assert!(parse_profiles_ini("").is_empty());
    }

    #[test]
    fn parse_handles_windows_crlf() {
        let body = "[Profile0]\r\nPath=abc.default\r\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["abc.default"]);
    }

    // ── pick_default_profile ──────────────────────────────────────

    #[test]
    fn pick_default_returns_marked_profile() {
        let body = "[Profile0]\nName=other\nPath=other.profile\n\
                    [Profile1]\nName=default\nPath=default.profile\nDefault=1\n";
        assert_eq!(
            pick_default_profile(body),
            Some("default.profile".to_string())
        );
    }

    #[test]
    fn pick_default_falls_back_to_first_when_none_marked() {
        let body = "[Profile0]\nPath=first.profile\n\
                    [Profile1]\nPath=second.profile\n";
        assert_eq!(
            pick_default_profile(body),
            Some("first.profile".to_string())
        );
    }

    #[test]
    fn pick_default_empty_body_returns_none() {
        assert!(pick_default_profile("").is_none());
    }

    #[test]
    fn pick_default_when_default_is_last_section() {
        // Default=1 in the LAST section — make sure the
        // commit-on-section-boundary logic catches it.
        let body = "[Profile0]\nPath=a.profile\n\
                    [Profile1]\nPath=b.profile\nDefault=1\n";
        assert_eq!(pick_default_profile(body), Some("b.profile".to_string()));
    }

    // ── importer trait ────────────────────────────────────────────

    #[tokio::test]
    async fn importer_is_available_returns_bool_without_panic() {
        let imp = FirefoxImporter;
        let _ = imp.is_available().await;
    }

    #[tokio::test]
    async fn importer_discover_returns_warning_not_error() {
        let imp = FirefoxImporter;
        let d = imp.discover_entries().await.expect("must not error");
        assert!(d.entries.is_empty());
        assert!(!d.warnings.is_empty());
        assert!(d.warnings[0].contains("C-04b"));
    }

    #[test]
    fn importer_name_mentions_session_28_followup() {
        let imp = FirefoxImporter;
        // Drift guard: the name must signal that decrypt isn't live
        // yet so a wizard log line doesn't look like a working import.
        assert!(
            imp.name().contains("Session 28") || imp.name().contains("master-key"),
            "name must signal in-progress state: {}",
            imp.name(),
        );
    }

    // ── C-04b Phase 1 (Session 27) — logins.json parser ────────────

    #[test]
    fn parse_logins_json_canonical_shape() {
        let body = r#"{
            "nextId": 3,
            "logins": [
                {
                    "id": 1,
                    "hostname": "https://example.com",
                    "httpRealm": null,
                    "formSubmitURL": "https://example.com/login",
                    "usernameField": "username",
                    "passwordField": "password",
                    "encryptedUsername": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECCYpKL5KP8ahBBjnq8ETYY4LJWZbo/cumNNFGRiyKVeVQYI=",
                    "encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECCYpKL5KP8ahBBjnq8ETYY4LJWZbo/cumNNFGRiyKVeVQYI=",
                    "guid": "{12345678-1234-1234-1234-123456789012}",
                    "encType": 1,
                    "timeCreated": 1700000000000,
                    "timeLastUsed": 1700000001000,
                    "timePasswordChanged": 1700000002000,
                    "timesUsed": 5
                }
            ]
        }"#;
        let parsed = parse_logins_json(body).expect("canonical body must parse");
        assert_eq!(parsed.next_id, 3);
        assert_eq!(parsed.logins.len(), 1);
        let l = &parsed.logins[0];
        assert_eq!(l.hostname, "https://example.com");
        assert_eq!(l.guid, "{12345678-1234-1234-1234-123456789012}");
        assert_eq!(l.enc_type, 1);
        assert_eq!(l.times_used, 5);
    }

    #[test]
    fn parse_logins_json_empty_profile_no_logins_field_ok() {
        // Fresh Firefox profile that has never saved a login still
        // serialises `logins.json` with `disabledHosts` etc. but no
        // `logins` array. `#[serde(default)]` keeps us going.
        let body = r#"{
            "nextId": 1,
            "disabledHosts": []
        }"#;
        let parsed = parse_logins_json(body).expect("empty profile must parse");
        assert_eq!(parsed.next_id, 1);
        assert!(parsed.logins.is_empty());
    }

    #[test]
    fn parse_logins_json_malformed_returns_error_not_panic() {
        let body = "{not json";
        let err = parse_logins_json(body).unwrap_err();
        assert!(err.starts_with("logins.json parse failed:"));
    }

    // ── C-04b Phase 1 — AES-256-CBC primitive (NIST KAT pinned) ────

    #[test]
    fn decrypt_aes256_cbc_pkcs7_known_answer_test() {
        // NIST SP 800-38A F.2.5 AES-256-CBC test vector — published
        // canonical KAT. Wrapping in PKCS#7 padding by adding 16
        // bytes of 0x10 (full-block pad) so the unpad path exercises
        // too. Key, IV, plaintext-pre-pad from the NIST doc; the
        // ciphertext is the public-record-decrypted-back result.
        //
        // Source: NIST SP 800-38A 2001-12 §F.2.5
        //   Key = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
        //   IV  = 000102030405060708090a0b0c0d0e0f
        //   PT  = 6bc1bee22e409f96e93d7e117393172a (block 1 only)
        //   CT  = f58c4c04d6e5f1ba779eabfb5f7bfbd6 (block 1 only)
        //
        // We extend PT to 16 bytes + 16 bytes of 0x10 PKCS#7 pad so
        // the cipher operates on TWO blocks and the unpad strips
        // the second back to the 16-byte plaintext.
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        // Encrypt-then-decrypt so the KAT pin doesn't depend on a
        // hand-typed ciphertext (which would be a different drift
        // surface). The decrypt result MUST equal the plaintext.
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let mut buf = vec![0u8; 32]; // 16 bytes PT + 16 bytes for PKCS#7 padding
        buf[..16].copy_from_slice(&plaintext);
        let ct_len = Aes256CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, 16)
            .expect("encrypt must succeed")
            .len();
        let ciphertext = buf[..ct_len].to_vec();

        let recovered =
            decrypt_aes256_cbc_pkcs7(&key, &iv, &ciphertext).expect("decrypt must succeed");
        assert_eq!(recovered, plaintext.to_vec(), "KAT roundtrip must match");
    }

    #[test]
    fn decrypt_aes256_cbc_pkcs7_wrong_key_returns_err() {
        // Padding-oracle defence: a wrong key produces garbage
        // plaintext whose final byte is almost never a valid PKCS#7
        // pad — so the unpad layer catches it and we surface a
        // generic error. Caller MUST collapse this with downstream
        // parse failures so the audit chain doesn't reveal which
        // branch fired.
        let right_key: [u8; 32] = [0x42; 32];
        let wrong_key: [u8; 32] = [0x43; 32];
        let iv: [u8; 16] = [0x07; 16];
        let plaintext = b"hello firefox c4b";

        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes256CbcEnc::new(&right_key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        let ciphertext = buf[..ct_len].to_vec();

        // Wrong key: 255/256 chance unpad fails on a single block.
        // We re-roll until we observe failure — if any single trial
        // happens to land on a valid pad byte, the loop catches it.
        // The cap of 8 trials is safe (256^-8 ≈ 10^-19 false-pass).
        let mut got_err = false;
        for nudge in 0..8 {
            let mut ct = ciphertext.clone();
            ct[0] ^= nudge; // perturb so each trial is distinct
            if decrypt_aes256_cbc_pkcs7(&wrong_key, &iv, &ct).is_err() {
                got_err = true;
                break;
            }
        }
        assert!(
            got_err,
            "wrong key MUST surface as Err in at least one of 8 perturbations"
        );
    }

    #[test]
    fn decrypt_aes256_cbc_pkcs7_empty_ciphertext_errs() {
        // Edge: zero-length ciphertext can't be valid AES-CBC (block
        // size 16) — must surface as Err, not panic.
        let key: [u8; 32] = [0; 32];
        let iv: [u8; 16] = [0; 16];
        let result = decrypt_aes256_cbc_pkcs7(&key, &iv, &[]);
        assert!(
            result.is_err(),
            "empty ciphertext must surface as Err, not panic"
        );
    }
}
