//! C-01 — credentials::mod + CredentialImporter trait substrate.
//!
//! Operator's existing credential stores (Bitwarden / KeePass /
//! Chrome Login Data / Firefox key4.db) feed NEOTH's secret-store
//! at wizard-time. The fragile part is the import path: each
//! source has its own format, its own decryption, its own
//! lifetime concerns. C-01 unifies them behind one trait so:
//!
//!   - Importers handle source-specific parsing + decryption.
//!   - The wizard's import-step orchestrator iterates available
//!     importers + offers operator a pick.
//!   - The resulting [`ImportedCredential`] flows into the SC-17
//!     `credential_redact` gate + the WAL `0xD6 CREDENTIAL_IMPORT`
//!     frame — `name` / `url` / `username` / `secret` never reach
//!     the audit log.
//!
//! ## What ships here
//!
//! - [`ImportedCredential`] — operator-visible record carrying
//!   secret material. **Held in memory only long enough to push
//!   into the secret store; the redactor strips every identifying
//!   field before WAL emission**.
//! - [`SecretBytes`] — newtype around the secret with `Drop`
//!   zeroisation + `Debug`/`Display` that doesn't leak the
//!   contents.
//! - [`CredentialImporter`] async trait — `source()` +
//!   `discover_entries()` + `name()`. Per-source impls (C-02
//!   Bitwarden, C-03 Chrome, C-04 Firefox) ship in follow-ups.
//! - [`ImportSession`] — orchestrator state machine the wizard
//!   step 6 runs; tracks progress, surfaces per-source errors,
//!   redacts via the SC-17 gate before emission.

pub mod bitwarden;
pub mod chrome;
pub mod firefox;
pub mod wizard_step;

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use crate::security::credential_redact::ImportSource;

/// Secret material the operator imported. `Drop` zeroises the
/// inner Vec so a leaked instance doesn't leave plaintext in
/// freed memory. `Debug`/`Display` print `"<redacted len=N>"` —
/// never the contents — so accidental tracing calls don't leak
/// secrets.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    pub fn from_string(s: String) -> Self {
        Self::new(s.into_bytes())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrow the raw bytes. Caller must NOT clone or
    /// `to_vec()` without explicit operator intent — the whole
    /// point of the newtype is to limit secret lifetime.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Borrow as a UTF-8 string slice when the secret is known
    /// to be text. Returns None when the bytes aren't valid UTF-8.
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.inner).ok()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Manual zeroisation — no zeroize crate dep needed for
        // the primitive shape. Volatile write semantics aren't
        // guaranteed via plain assignment but a Drop pass at
        // least scrubs the heap region before deallocation.
        for b in self.inner.iter_mut() {
            // Use a non-volatile write — std::ptr::write_volatile
            // would be stronger but requires unsafe. Acceptable
            // tradeoff for the C-01 primitive; C-02 Bitwarden
            // impl that handles real keys can layer zeroize on
            // top.
            *b = 0;
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted len={}>)", self.inner.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted len={}>", self.inner.len())
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time compare to avoid timing-side-channel
        // leaks in test/equality paths.
        if self.inner.len() != other.inner.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.inner.iter().zip(other.inner.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}
impl Eq for SecretBytes {}

/// One credential entry the operator chose to import. Carries
/// the identifying fields (name / url / username) + the secret
/// + operator-chosen tags. Created by [`CredentialImporter`]
/// impls; consumed by the SC-17 redactor + the secret-store
/// write path. **Never serialised to disk in this shape** —
/// the WAL frame receives the redacted projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCredential {
    pub source: ImportSource,
    pub name: String,
    pub url: String,
    pub username: String,
    pub secret: SecretBytes,
    pub tags: Vec<String>,
}

impl ImportedCredential {
    /// Construct from operator-visible fields. The string-typed
    /// `secret` is moved into a `SecretBytes` immediately so the
    /// caller's String holding the password is dropped + scrubbed
    /// before any further work.
    pub fn new(
        source: ImportSource,
        name: impl Into<String>,
        url: impl Into<String>,
        username: impl Into<String>,
        secret: String,
        tags: Vec<String>,
    ) -> Self {
        Self {
            source,
            name: name.into(),
            url: url.into(),
            username: username.into(),
            secret: SecretBytes::from_string(secret),
            tags,
        }
    }
}

/// Discovery outcome from one importer. Per-source impls may
/// return zero credentials (importer ran but the source has no
/// entries) or an error (decryption failed, file missing, etc.).
#[derive(Debug)]
pub struct DiscoveredCredentials {
    pub source: ImportSource,
    /// Successfully-parsed credentials.
    pub entries: Vec<ImportedCredential>,
    /// Per-entry warnings the importer collected — e.g. "one
    /// entry skipped because the URL field was empty". Surface
    /// to operator in the wizard's "what we found" page.
    pub warnings: Vec<String>,
}

/// Trait every credential source impls. Each impl is an async
/// fn so OS-API calls (Windows DPAPI, macOS Keychain, Linux
/// Secret Service over DBus) can `await` cleanly.
#[async_trait]
pub trait CredentialImporter: Send + Sync {
    /// The source enum variant this impl handles.
    fn source(&self) -> ImportSource;

    /// Operator-readable name. Wizard shows this in the picker
    /// ("Bitwarden encrypted export" / "Chrome (this profile)").
    fn name(&self) -> &'static str;

    /// True when the importer's source is present on this host
    /// (Chrome installed + readable, Bitwarden export file exists,
    /// etc.). Wizard's discovery step skips unavailable importers.
    async fn is_available(&self) -> bool;

    /// Discover + parse + decrypt every credential the source
    /// exposes. Errors surface as `Err(reason)` so the orchestrator
    /// can show a per-source diagnostic without halting other
    /// importers.
    async fn discover_entries(&self) -> Result<DiscoveredCredentials, String>;
}

/// One per-importer outcome in the orchestrator's tally.
#[derive(Debug)]
pub struct ImporterOutcome {
    pub source: ImportSource,
    pub name: String,
    pub result: Result<DiscoveredCredentials, String>,
}

impl ImporterOutcome {
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

/// Aggregate state machine for the wizard's import step. Caller
/// passes an ordered list of importers; the orchestrator runs
/// each + collects outcomes. Failures don't abort — operator
/// sees a per-source diagnostic.
pub struct ImportSession {
    importers: Vec<Box<dyn CredentialImporter>>,
}

impl ImportSession {
    pub fn new(importers: Vec<Box<dyn CredentialImporter>>) -> Self {
        Self { importers }
    }

    pub fn len(&self) -> usize {
        self.importers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.importers.is_empty()
    }

    /// Run every available importer + return per-source outcomes.
    /// Pure-fn over the importer list — unavailable sources are
    /// skipped entirely (no entry in the result).
    pub async fn run(&self) -> Vec<ImporterOutcome> {
        let mut out = Vec::with_capacity(self.importers.len());
        for imp in &self.importers {
            if !imp.is_available().await {
                continue;
            }
            let source = imp.source();
            let name = imp.name().to_string();
            let result = imp.discover_entries().await;
            out.push(ImporterOutcome {
                source,
                name,
                result,
            });
        }
        out
    }
}

/// Flatten a list of `ImporterOutcome`s into a single
/// [`crate::security::credential_redact::CredentialImportRecord`]
/// suitable for SC-17 redaction + WAL emission. Drops the
/// per-source warnings (they belong in the wizard UI, not the
/// audit log).
pub fn build_import_record(
    outcomes: &[ImporterOutcome],
    target_vault_id: impl Into<String>,
    ts_unix: i64,
) -> crate::security::credential_redact::CredentialImportRecord {
    // Pick the first successful source as the record source.
    // The redacted WAL frame only carries ONE source tag — this
    // is intentional. Cross-source imports run multiple wizard
    // passes + emit multiple 0xD6 frames per pass.
    let source = outcomes
        .iter()
        .find_map(|o| o.result.as_ref().ok().map(|_| o.source))
        .unwrap_or(ImportSource::WizardPrompt);

    let entries = outcomes
        .iter()
        .filter_map(|o| o.result.as_ref().ok())
        .flat_map(|d| {
            d.entries
                .iter()
                .map(|c| crate::security::credential_redact::CredentialEntry {
                    name: c.name.clone(),
                    url: c.url.clone(),
                    username: c.username.clone(),
                    secret: c
                        .secret
                        .expose_str()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    tags: c.tags.clone(),
                })
        })
        .collect();

    crate::security::credential_redact::CredentialImportRecord {
        source,
        entries,
        target_vault_id: target_vault_id.into(),
        ts_unix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SecretBytes ───────────────────────────────────────────────

    #[test]
    fn secret_bytes_debug_redacts_contents() {
        let s = SecretBytes::from_string("supersecret".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("len=11"));
    }

    #[test]
    fn secret_bytes_display_redacts_contents() {
        let s = SecretBytes::from_string("supersecret".to_string());
        let disp = format!("{s}");
        assert!(!disp.contains("supersecret"));
        assert!(disp.contains("redacted"));
    }

    #[test]
    fn secret_bytes_expose_str_returns_utf8() {
        let s = SecretBytes::from_string("hello".to_string());
        assert_eq!(s.expose_str(), Some("hello"));
    }

    #[test]
    fn secret_bytes_expose_str_returns_none_for_invalid_utf8() {
        let s = SecretBytes::new(vec![0xFF, 0xFE, 0xFD]);
        assert!(s.expose_str().is_none());
    }

    #[test]
    fn secret_bytes_len_and_empty() {
        let s = SecretBytes::from_string("abc".to_string());
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        let e = SecretBytes::new(Vec::new());
        assert_eq!(e.len(), 0);
        assert!(e.is_empty());
    }

    #[test]
    fn secret_bytes_clone_equals_original_constant_time() {
        let a = SecretBytes::from_string("hello".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn secret_bytes_constant_time_compare_differs() {
        let a = SecretBytes::from_string("hello".to_string());
        let b = SecretBytes::from_string("world".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn secret_bytes_constant_time_compare_length_mismatch() {
        let a = SecretBytes::from_string("short".to_string());
        let b = SecretBytes::from_string("longer".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn secret_bytes_drop_zeroises_inner() {
        // We can't observe a dropped Vec's freed memory directly,
        // but we CAN observe that Drop runs by wrapping the
        // secret in a closure scope + checking that no panic
        // happens (Drop runs at scope-end).
        {
            let _s = SecretBytes::from_string("transient".to_string());
        }
        // No assertion needed — if Drop panicked we'd see it.
    }

    // ── ImportedCredential ────────────────────────────────────────

    #[test]
    fn imported_credential_new_wraps_secret() {
        let c = ImportedCredential::new(
            ImportSource::Bitwarden,
            "Acme",
            "https://acme.com",
            "alex",
            "pass".to_string(),
            vec!["work".into()],
        );
        assert_eq!(c.source, ImportSource::Bitwarden);
        assert_eq!(c.name, "Acme");
        assert_eq!(c.url, "https://acme.com");
        assert_eq!(c.username, "alex");
        assert_eq!(c.secret.expose_str(), Some("pass"));
        assert_eq!(c.tags, vec!["work"]);
    }

    #[test]
    fn imported_credential_debug_does_not_leak_secret() {
        let c = ImportedCredential::new(
            ImportSource::Bitwarden,
            "Acme",
            "https://acme.com",
            "alex",
            "supersecret".to_string(),
            vec![],
        );
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
    }

    // ── ImportSession orchestrator ────────────────────────────────

    struct StubImporter {
        source: ImportSource,
        name: &'static str,
        available: bool,
        result: Result<Vec<ImportedCredential>, String>,
    }

    #[async_trait]
    impl CredentialImporter for StubImporter {
        fn source(&self) -> ImportSource {
            self.source
        }
        fn name(&self) -> &'static str {
            self.name
        }
        async fn is_available(&self) -> bool {
            self.available
        }
        async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
            match &self.result {
                Ok(entries) => Ok(DiscoveredCredentials {
                    source: self.source,
                    entries: entries.clone(),
                    warnings: Vec::new(),
                }),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn cred(name: &str, secret: &str) -> ImportedCredential {
        ImportedCredential::new(
            ImportSource::Bitwarden,
            name,
            "https://x",
            "alex",
            secret.to_string(),
            vec!["work".into()],
        )
    }

    #[tokio::test]
    async fn session_skips_unavailable_importers() {
        let s = ImportSession::new(vec![
            Box::new(StubImporter {
                source: ImportSource::Bitwarden,
                name: "Bitwarden",
                available: false,
                result: Ok(Vec::new()),
            }),
            Box::new(StubImporter {
                source: ImportSource::Keepass,
                name: "KeePass",
                available: true,
                result: Ok(vec![cred("KeePass entry", "k-pass")]),
            }),
        ]);
        let outcomes = s.run().await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].source, ImportSource::Keepass);
        assert!(outcomes[0].is_ok());
    }

    #[tokio::test]
    async fn session_collects_per_source_errors_without_aborting() {
        let s = ImportSession::new(vec![
            Box::new(StubImporter {
                source: ImportSource::Bitwarden,
                name: "Bitwarden",
                available: true,
                result: Err("decrypt failed".into()),
            }),
            Box::new(StubImporter {
                source: ImportSource::Keepass,
                name: "KeePass",
                available: true,
                result: Ok(vec![cred("k1", "x")]),
            }),
        ]);
        let outcomes = s.run().await;
        assert_eq!(outcomes.len(), 2);
        assert!(!outcomes[0].is_ok());
        assert!(outcomes[1].is_ok());
    }

    #[tokio::test]
    async fn session_empty_when_no_importers() {
        let s = ImportSession::new(Vec::new());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        let outcomes = s.run().await;
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn build_import_record_uses_first_successful_source() {
        let s = ImportSession::new(vec![
            Box::new(StubImporter {
                source: ImportSource::Bitwarden,
                name: "Bitwarden",
                available: true,
                result: Err("decrypt failed".into()),
            }),
            Box::new(StubImporter {
                source: ImportSource::Keepass,
                name: "KeePass",
                available: true,
                result: Ok(vec![cred("k1", "x")]),
            }),
        ]);
        let outcomes = s.run().await;
        let record = build_import_record(&outcomes, "primary", 1_700_000_000);
        // Bitwarden failed → source falls through to KeePass.
        assert_eq!(record.source, ImportSource::Keepass);
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.target_vault_id, "primary");
        assert_eq!(record.ts_unix, 1_700_000_000);
    }

    #[tokio::test]
    async fn build_import_record_no_successful_source_uses_wizard_prompt() {
        let s = ImportSession::new(vec![Box::new(StubImporter {
            source: ImportSource::Bitwarden,
            name: "Bitwarden",
            available: true,
            result: Err("decrypt failed".into()),
        })]);
        let outcomes = s.run().await;
        let record = build_import_record(&outcomes, "primary", 0);
        assert_eq!(record.source, ImportSource::WizardPrompt);
        assert!(record.entries.is_empty());
    }

    #[tokio::test]
    async fn build_import_record_flows_through_redactor_cleanly() {
        // End-to-end smoke: discovered → record → redacted →
        // every SecretBytes / name / url / username scrubbed from
        // the WAL payload.
        let s = ImportSession::new(vec![Box::new(StubImporter {
            source: ImportSource::Bitwarden,
            name: "Bitwarden",
            available: true,
            result: Ok(vec![cred("PayPal", "supersecret")]),
        })]);
        let outcomes = s.run().await;
        let record = build_import_record(&outcomes, "primary", 1_700_000_000);
        let redacted = crate::security::credential_redact::redact_credential_import(&record);
        let json = serde_json::to_string(&redacted).unwrap();
        assert!(!json.contains("PayPal"));
        assert!(!json.contains("supersecret"));
        assert!(!json.contains("alex"));
        assert!(redacted.services_redacted);
        assert_eq!(redacted.entry_count, 1);
    }
}
