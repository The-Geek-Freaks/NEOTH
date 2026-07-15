//! C-02 — Bitwarden importer.
//!
//! Operator exports their Bitwarden vault as either:
//!   - JSON (unencrypted) — straightforward parse.
//!   - encrypted_json (password-protected) — PBKDF2 + AES-CBC
//!     decrypt.
//!
//! This module ships the **unencrypted JSON** parser (the easier
//! path operators already use for "export → import to another
//! manager"). The encrypted variant lands in C-02b once we wire
//! `aes-gcm` + `pbkdf2` crates behind a feature flag.
//!
//! **A5 SC-17 hardening**: every JSON parse runs through a
//! depth-limited `serde_json::Deserializer` (max 64 nested
//! objects) so an adversarial export with `{{{...}}}` 10k deep
//! can't blow the stack.
//!
//! Format reference: Bitwarden's documented JSON export schema
//! (`folders[]`, `items[]` with `login.username`, `login.password`,
//! `login.uris[].uri`, `name`, `notes`, `tags?`).

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::credentials::{
    CredentialImporter, DiscoveredCredentials, ImportSource, ImportedCredential,
};
use crate::secret::SecretString;

/// Maximum nesting depth allowed when parsing a Bitwarden export.
/// Adversarial JSON with deeper nesting is rejected to prevent
/// stack-overflow attacks (SC-17 hardening). 64 is well above
/// any plausible legitimate Bitwarden export shape.
pub const MAX_NESTING_DEPTH: usize = 64;

/// One Bitwarden export item — the subset of fields C-02 cares
/// about. Tolerant — extra fields in the export drop, missing
/// fields default. `#[serde(default)]` everywhere keeps backwards-
/// compat with older Bitwarden export shapes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BwItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: String,
    /// 1 = login, 2 = secure note, 3 = card, 4 = identity. C-02
    /// only ingests `type == 1` (logins).
    #[serde(default, rename = "type")]
    item_type: u32,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default, rename = "folderId")]
    folder_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BwExport {
    /// `true` for a password-protected (`encrypted_json`) export. The
    /// plaintext parser must REJECT these — an encrypted export has no
    /// `items`/`folders` at top level, so without this guard it parsed
    /// to an empty vault silently (C-02b bug). The decrypt path lives in
    /// [`crate::credentials::bitwarden_encrypted`]; the importer routes
    /// to it automatically (see [`BitwardenJsonImporter::discover_entries`]).
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

/// Cheap pre-flight: is this export the password-protected
/// (`encrypted: true`) variant? Tolerant — a parse failure (truncated
/// file, not-JSON) returns `false` so the caller falls through to the
/// plaintext parser, which surfaces the real parse error. Used by the
/// importer + wizard to route encrypted exports to the decrypt path.
pub fn export_is_encrypted(body: &str) -> bool {
    #[derive(Deserialize)]
    struct EncFlag {
        #[serde(default)]
        encrypted: bool,
    }
    serde_json::from_str::<EncFlag>(body)
        .map(|f| f.encrypted)
        .unwrap_or(false)
}

/// Maximum bytes read when PEEKING an export to decide the wizard's
/// password prompt (C-02b). A real Bitwarden export — even tens of
/// thousands of logins — is a few MB; 16 MiB is well above any plausible
/// vault while bounding the wizard's synchronous read so a pathological
/// file can't exhaust memory before the importer runs.
pub const MAX_PEEK_BYTES: u64 = 16 * 1024 * 1024;

/// Bounded encrypted-variant detection for the wizard's prompt decision:
/// reads at most [`MAX_PEEK_BYTES`] of `path` and checks the `encrypted`
/// flag. A file larger than the cap, unreadable, or not valid JSON within
/// the cap returns `false` — the importer then reads + handles it
/// authoritatively (an encrypted export with no password surfaces a clear
/// error, never a silent empty vault). Bounding here replaces the
/// unbounded synchronous `read_to_string` the wizard would otherwise run.
pub fn file_is_encrypted_export(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if file.take(MAX_PEEK_BYTES).read_to_end(&mut buf).is_err() {
        return false;
    }
    match std::str::from_utf8(&buf) {
        Ok(s) => export_is_encrypted(s),
        Err(_) => false,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BwFolder {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

/// Importer for the Bitwarden JSON export — handles BOTH the plaintext
/// (`encrypted: false`) and the password-protected (`encrypted: true`)
/// variants. Mirrors the Firefox importer precedent: a single importer
/// carries an OPTIONAL secret (`password`) rather than splitting into two
/// types. The export format is auto-detected at `discover_entries` time;
/// an encrypted export with no password supplied surfaces a clear error
/// (never a silent empty vault).
pub struct BitwardenJsonImporter {
    pub export_path: PathBuf,
    /// Export password for the encrypted variant. `None` for plaintext
    /// exports (the common case) — the wizard's interactive branch fills
    /// this via [`BitwardenJsonImporter::with_password`] after prompting.
    password: Option<SecretString>,
}

impl BitwardenJsonImporter {
    pub fn new(export_path: impl Into<PathBuf>) -> Self {
        Self {
            export_path: export_path.into(),
            password: None,
        }
    }

    /// Attach the export password for the encrypted variant. Builder so
    /// the plaintext call site (`new`) stays a one-arg constructor.
    pub fn with_password(mut self, password: SecretString) -> Self {
        self.password = Some(password);
        self
    }
}

#[async_trait]
impl CredentialImporter for BitwardenJsonImporter {
    fn source(&self) -> ImportSource {
        ImportSource::Bitwarden
    }

    fn name(&self) -> &'static str {
        "Bitwarden (JSON export)"
    }

    async fn is_available(&self) -> bool {
        // Available iff the export file exists + is readable.
        tokio::fs::metadata(&self.export_path).await.is_ok()
    }

    async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
        let body = tokio::fs::read_to_string(&self.export_path)
            .await
            .map_err(|e| format!("read {}: {e}", self.export_path.display()))?;
        if export_is_encrypted(&body) {
            // Password-protected export → decrypt first, then reuse the
            // plaintext parser on the recovered vault JSON.
            let password = self.password.as_ref().ok_or_else(|| {
                "encrypted Bitwarden export — re-run the import with the export password \
                 (the encrypted variant cannot be read without it)"
                    .to_string()
            })?;
            let plaintext = crate::credentials::bitwarden_encrypted::parse_and_decrypt(
                &body,
                password.expose(),
            )
            .map_err(|e| format!("decrypt Bitwarden export: {e}"))?;
            parse_export_str(&plaintext)
        } else {
            parse_export_str(&body)
        }
    }
}

/// Pure-fn parser — tests exercise this without touching the
/// filesystem. SC-17 hardening: depth-limited Deserializer
/// rejects adversarial nested JSON.
pub fn parse_export_str(body: &str) -> Result<DiscoveredCredentials, String> {
    // Quick depth check before handing to serde — pre-validate
    // {/}/[/] nesting to reject pathological inputs upfront.
    if !is_within_depth_limit(body, MAX_NESTING_DEPTH) {
        return Err(format!(
            "Bitwarden export exceeds max nesting depth {MAX_NESTING_DEPTH} \
             (adversarial JSON suspected — SC-17 reject)",
        ));
    }
    let export: BwExport = serde_json::from_str(body).map_err(|e| format!("parse JSON: {e}"))?;

    // C-02b: a password-protected export carries `encrypted: true` and no
    // top-level items — reject it with a clear message instead of silently
    // returning an empty vault. The importer routes encrypted exports to the
    // decrypt path before reaching here; this guard catches direct callers.
    if export.encrypted {
        return Err(
            "encrypted Bitwarden export detected (`encrypted: true`) — supply the export \
             password so NEOTH can decrypt it first"
                .to_string(),
        );
    }

    // Folder id → tag mapping.
    let folder_tag: std::collections::HashMap<String, String> = export
        .folders
        .iter()
        .filter(|f| !f.name.is_empty())
        .map(|f| (f.id.clone(), f.name.clone()))
        .collect();

    let mut entries: Vec<ImportedCredential> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for item in export.items {
        // Only logins (type 1).
        if item.item_type != 1 {
            continue;
        }
        let login = match item.login {
            Some(l) => l,
            None => {
                warnings.push(format!(
                    "skipped item {:?}: type=1 but login block missing",
                    item.name,
                ));
                continue;
            }
        };
        let password = match login.password {
            Some(p) if !p.is_empty() => p,
            _ => {
                warnings.push(format!("skipped item {:?}: empty password", item.name,));
                continue;
            }
        };
        let username = login.username.unwrap_or_default();
        let url = login
            .uris
            .into_iter()
            .find(|u| !u.uri.is_empty())
            .map(|u| u.uri)
            .unwrap_or_default();
        let mut tags = Vec::new();
        if let Some(folder_id) = item.folder_id.as_ref()
            && let Some(name) = folder_tag.get(folder_id)
        {
            tags.push(name.clone());
        }
        entries.push(ImportedCredential::new(
            ImportSource::Bitwarden,
            item.name,
            url,
            username,
            password,
            tags,
        ));
    }

    Ok(DiscoveredCredentials {
        source: ImportSource::Bitwarden,
        entries,
        warnings,
    })
}

/// Pre-validate nesting depth. Counts open/close brace+bracket
/// pairs in a single pass over the byte string (string-literal
/// awareness via simple escape tracking). Returns false the
/// instant the depth exceeds `max`.
pub fn is_within_depth_limit(body: &str, max: usize) -> bool {
    let bytes = body.as_bytes();
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── depth limit ───────────────────────────────────────────────

    #[test]
    fn within_depth_returns_true_for_normal_export() {
        let body = r#"{
            "folders": [{"id":"a","name":"work"}],
            "items": [{
                "name": "PayPal",
                "type": 1,
                "login": {"username":"sam","password":"x","uris":[{"uri":"https://paypal.com"}]}
            }]
        }"#;
        assert!(is_within_depth_limit(body, MAX_NESTING_DEPTH));
    }

    #[test]
    fn within_depth_rejects_adversarial_deep_nesting() {
        // 100 nested objects.
        let mut deep = String::new();
        for _ in 0..100 {
            deep.push('{');
        }
        deep.push_str("\"x\":1");
        for _ in 0..100 {
            deep.push('}');
        }
        assert!(!is_within_depth_limit(&deep, MAX_NESTING_DEPTH));
    }

    #[test]
    fn within_depth_ignores_braces_inside_strings() {
        let body = r#"{"name":"sam { has { quotes } inside"}"#;
        assert!(is_within_depth_limit(body, 2));
    }

    #[test]
    fn within_depth_handles_escaped_quotes() {
        let body = r#"{"name":"contains \" escaped quote"}"#;
        assert!(is_within_depth_limit(body, 2));
    }

    // ── parse_export_str ──────────────────────────────────────────

    #[test]
    fn parse_empty_export_returns_empty_entries() {
        let result = parse_export_str(r#"{"folders":[],"items":[]}"#).unwrap();
        assert!(result.entries.is_empty());
        assert!(result.warnings.is_empty());
        assert_eq!(result.source, ImportSource::Bitwarden);
    }

    #[test]
    fn parse_single_login_extracts_every_field() {
        let body = r#"{
            "folders":[{"id":"f1","name":"work"}],
            "items":[{
                "name":"PayPal",
                "type":1,
                "folderId":"f1",
                "login":{
                    "username":"sam@example.com",
                    "password":"S3cret!",
                    "uris":[{"uri":"https://paypal.com"}]
                }
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert_eq!(r.entries.len(), 1);
        let c = &r.entries[0];
        assert_eq!(c.name, "PayPal");
        assert_eq!(c.url, "https://paypal.com");
        assert_eq!(c.username, "sam@example.com");
        assert_eq!(c.secret.expose_str(), Some("S3cret!"));
        assert_eq!(c.tags, vec!["work"]);
    }

    #[test]
    fn parse_skips_non_login_items() {
        let body = r#"{
            "folders":[],
            "items":[
                {"name":"My Note","type":2,"notes":"secret thoughts"},
                {"name":"Card","type":3},
                {"name":"Identity","type":4},
                {"name":"Real Login","type":1,"login":{"username":"u","password":"p","uris":[{"uri":"x"}]}}
            ]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].name, "Real Login");
    }

    #[test]
    fn parse_skips_login_with_empty_password_with_warning() {
        let body = r#"{
            "folders":[],
            "items":[{
                "name":"NoPass","type":1,
                "login":{"username":"u","password":"","uris":[]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert!(r.entries.is_empty());
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("empty password"));
        assert!(r.warnings[0].contains("NoPass"));
    }

    #[test]
    fn parse_skips_login_with_missing_password_field() {
        let body = r#"{
            "items":[{
                "name":"NoPasswordField","type":1,
                "login":{"username":"u","uris":[]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert!(r.entries.is_empty());
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn parse_skips_type1_item_with_no_login_block() {
        let body = r#"{
            "items":[{"name":"Broken","type":1}]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert!(r.entries.is_empty());
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("login block missing"));
    }

    #[test]
    fn parse_uses_first_non_empty_uri() {
        let body = r#"{
            "items":[{
                "name":"WithEmptyUri","type":1,
                "login":{"username":"u","password":"p","uris":[{"uri":""},{"uri":"https://real.com"}]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert_eq!(r.entries[0].url, "https://real.com");
    }

    #[test]
    fn parse_empty_username_left_as_empty_string() {
        let body = r#"{
            "items":[{
                "name":"NoUser","type":1,
                "login":{"password":"p","uris":[{"uri":"x"}]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert_eq!(r.entries[0].username, "");
    }

    #[test]
    fn parse_no_folder_id_means_no_tag() {
        let body = r#"{
            "folders":[{"id":"f1","name":"work"}],
            "items":[{
                "name":"Unfoldered","type":1,
                "login":{"username":"u","password":"p","uris":[{"uri":"x"}]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert!(r.entries[0].tags.is_empty());
    }

    #[test]
    fn parse_unknown_folder_id_falls_back_to_no_tag() {
        let body = r#"{
            "folders":[{"id":"f1","name":"work"}],
            "items":[{
                "name":"X","type":1,
                "folderId":"f99",
                "login":{"username":"u","password":"p","uris":[{"uri":"x"}]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert!(r.entries[0].tags.is_empty());
    }

    #[test]
    fn parse_rejects_oversize_depth_with_sc17_message() {
        let mut deep = String::from("{\"items\":");
        for _ in 0..100 {
            deep.push('[');
        }
        deep.push_str("\"x\"");
        for _ in 0..100 {
            deep.push(']');
        }
        deep.push('}');
        let err = parse_export_str(&deep).unwrap_err();
        assert!(err.contains("nesting depth"));
        assert!(err.contains("SC-17"));
    }

    #[test]
    fn parse_invalid_json_returns_err() {
        let err = parse_export_str("not json at all").unwrap_err();
        assert!(err.contains("parse JSON"));
    }

    #[test]
    fn parse_ignores_unknown_fields_tolerantly() {
        let body = r#"{
            "encrypted":false,
            "schemaVersion":42,
            "future_field":"future_value",
            "items":[{
                "name":"X","type":1,"future":"x",
                "login":{"username":"u","password":"p","uris":[{"uri":"x"}]}
            }]
        }"#;
        let r = parse_export_str(body).unwrap();
        assert_eq!(r.entries.len(), 1);
    }

    // ── importer trait integration ────────────────────────────────

    #[tokio::test]
    async fn importer_is_available_false_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let imp = BitwardenJsonImporter::new(dir.path().join("no-export.json"));
        assert!(!imp.is_available().await);
    }

    #[tokio::test]
    async fn importer_is_available_true_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(&path, "{}").unwrap();
        let imp = BitwardenJsonImporter::new(&path);
        assert!(imp.is_available().await);
    }

    #[tokio::test]
    async fn importer_discover_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        let body = r#"{
            "folders":[{"id":"f1","name":"work"}],
            "items":[{
                "name":"PayPal","type":1,"folderId":"f1",
                "login":{"username":"sam","password":"x","uris":[{"uri":"https://paypal.com"}]}
            }]
        }"#;
        std::fs::write(&path, body).unwrap();
        let imp = BitwardenJsonImporter::new(&path);
        let d = imp.discover_entries().await.unwrap();
        assert_eq!(d.source, ImportSource::Bitwarden);
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].secret.expose_str(), Some("x"));
    }

    #[tokio::test]
    async fn importer_discover_missing_file_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let imp = BitwardenJsonImporter::new(dir.path().join("no-export.json"));
        let err = imp.discover_entries().await.unwrap_err();
        assert!(err.contains("read"));
    }

    // ── C-02b: encrypted-export detection + decrypt routing ───────────

    /// Build a real password-protected Bitwarden export envelope around
    /// `vault_json`, using the SAME AES-256-CBC + HMAC-SHA256 + PBKDF2
    /// construction the decrypt path expects. Mirrors the encrypted
    /// module's own test harness so the importer round-trip exercises
    /// the production decrypt code, not a stub.
    fn build_synthetic_encrypted_export(
        password: &str,
        salt: &str,
        iters: u32,
        vault_json: &str,
    ) -> String {
        use base64::Engine as _;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type HmacSha256 = Hmac<Sha256>;

        let (enc_key, mac_key) = crate::credentials::bitwarden_encrypted::derive_keys_pbkdf2(
            password.as_bytes(),
            salt.as_bytes(),
            iters,
        );
        let enc_string = |plaintext: &[u8], iv: &[u8; 16]| -> String {
            let mut buf = vec![0u8; plaintext.len() + 16];
            buf[..plaintext.len()].copy_from_slice(plaintext);
            let ct_len = Aes256CbcEnc::new((&enc_key).into(), iv.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                .expect("encrypt must succeed")
                .len();
            buf.truncate(ct_len);
            let mut h = HmacSha256::new_from_slice(&mac_key).expect("HMAC accepts any key len");
            h.update(iv);
            h.update(&buf);
            let mac = h.finalize().into_bytes();
            format!(
                "2.{}|{}|{}",
                base64::engine::general_purpose::STANDARD.encode(iv),
                base64::engine::general_purpose::STANDARD.encode(&buf),
                base64::engine::general_purpose::STANDARD.encode(mac),
            )
        };
        let validator = enc_string(b"neoth-validator", &[0xAB; 16]);
        let data_enc = enc_string(vault_json.as_bytes(), &[0xCD; 16]);
        format!(
            r#"{{"encrypted":true,"passwordProtected":true,"salt":"{salt}","kdfType":0,"kdfIterations":{iters},"encKeyValidation_DO_NOT_EDIT":"{validator}","data":"{data_enc}"}}"#
        )
    }

    #[test]
    fn export_is_encrypted_detects_flag() {
        assert!(export_is_encrypted(r#"{"encrypted":true,"data":"x"}"#));
        assert!(!export_is_encrypted(r#"{"encrypted":false,"items":[]}"#));
        // absent flag == plaintext export
        assert!(!export_is_encrypted(r#"{"items":[]}"#));
        // tolerant: non-JSON falls through to the plaintext parser
        assert!(!export_is_encrypted("not json at all"));
    }

    #[test]
    fn parse_export_str_rejects_encrypted_export() {
        let err = parse_export_str(r#"{"encrypted":true,"data":"2.a|b|c"}"#).unwrap_err();
        assert!(err.contains("encrypted Bitwarden export"), "got: {err}");
        assert!(err.contains("password"), "got: {err}");
    }

    #[tokio::test]
    async fn encrypted_importer_without_password_errors_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.json");
        std::fs::write(&path, r#"{"encrypted":true,"data":"2.a|b|c"}"#).unwrap();
        // No password attached → must surface a clear, actionable error,
        // NOT a silent empty vault (the C-02b bug).
        let imp = BitwardenJsonImporter::new(&path);
        let err = imp.discover_entries().await.unwrap_err();
        assert!(err.contains("encrypted"), "got: {err}");
        assert!(err.contains("password"), "got: {err}");
    }

    #[tokio::test]
    async fn encrypted_importer_round_trip_decrypts_and_parses() {
        let vault = r#"{"folders":[],"items":[{"name":"PayPal","type":1,"login":{"username":"sam","password":"S3cret!","uris":[{"uri":"https://paypal.com"}]}}]}"#;
        let body = build_synthetic_encrypted_export("hunter2", "sam@example.com", 100_000, vault);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.json");
        std::fs::write(&path, body).unwrap();
        let imp =
            BitwardenJsonImporter::new(&path).with_password(SecretString::new("hunter2".into()));
        let d = imp.discover_entries().await.unwrap();
        assert_eq!(d.entries.len(), 1, "decrypted vault must yield the login");
        assert_eq!(d.entries[0].name, "PayPal");
        assert_eq!(d.entries[0].username, "sam");
        assert_eq!(d.entries[0].secret.expose_str(), Some("S3cret!"));
    }

    #[tokio::test]
    async fn encrypted_importer_wrong_password_surfaces_decrypt_error() {
        let body = build_synthetic_encrypted_export(
            "correct-horse",
            "s@e.com",
            100_000,
            r#"{"items":[]}"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.json");
        std::fs::write(&path, body).unwrap();
        let imp =
            BitwardenJsonImporter::new(&path).with_password(SecretString::new("wrong".into()));
        let err = imp.discover_entries().await.unwrap_err();
        // The decrypt error (WrongPassword) is wrapped, never silently empty.
        assert!(err.contains("decrypt Bitwarden export"), "got: {err}");
        // Pin the INNER error too — a regression that drops `{e}` from the
        // wrapper (leaving only the prefix) would still pass the line above.
        assert!(
            err.contains("password rejected") || err.contains("HMAC"),
            "inner error must stay actionable (WrongPassword), got: {err}"
        );
    }

    #[tokio::test]
    async fn encrypted_importer_account_key_export_surfaces_unsupported_error() {
        // `encrypted:true` + `passwordProtected:false` = the Bitwarden
        // account-key export path, which the decrypt module rejects as
        // unsupported. The importer must surface that as a clear error
        // (an operator on the account-key path hits this in production).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.json");
        std::fs::write(
            &path,
            r#"{"encrypted":true,"passwordProtected":false,"salt":"","kdfType":0,"kdfIterations":600000,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.d|e|f"}"#,
        )
        .unwrap();
        let imp =
            BitwardenJsonImporter::new(&path).with_password(SecretString::new("anything".into()));
        let err = imp.discover_entries().await.unwrap_err();
        assert!(err.contains("decrypt Bitwarden export"), "got: {err}");
        assert!(
            err.contains("not password-protected") || err.contains("account-key"),
            "account-key export must surface an unsupported-path error, got: {err}"
        );
    }

    #[test]
    fn file_is_encrypted_export_bounded_detection() {
        let dir = tempfile::tempdir().unwrap();
        let enc = dir.path().join("enc.json");
        std::fs::write(&enc, r#"{"encrypted":true,"data":"x"}"#).unwrap();
        assert!(file_is_encrypted_export(&enc), "encrypted export detected");
        let plain = dir.path().join("plain.json");
        std::fs::write(&plain, r#"{"items":[]}"#).unwrap();
        assert!(!file_is_encrypted_export(&plain), "plaintext export");
        // Missing file → false, no panic (the importer surfaces the real
        // read error later).
        assert!(!file_is_encrypted_export(&dir.path().join("nope.json")));
    }
}
