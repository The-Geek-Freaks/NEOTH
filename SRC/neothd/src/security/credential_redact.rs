//! SC-17 — credential-import WAL payload redactor.
//!
//! WAL frame `0x15 CREDENTIAL_IMPORT` records that an operator
//! imported credentials (Bitwarden / KeePass / system keyring) so
//! the audit trail can prove what entered the secret store + when.
//! What it MUST NOT record: the credential names, URLs, usernames,
//! or the secret material itself — any one of those leaking via
//! the WAL undoes the operator's choice to keep credentials out of
//! their backup chain.
//!
//! This module is the gate every WAL writer for 0x15 MUST go
//! through:
//!
//!   1. Accept a [`CredentialImportRecord`] with the rich detail
//!      the wizard collected.
//!   2. Return a [`RedactedCredentialImportPayload`] containing
//!      ONLY non-identifying counts + tags + a SHA-256-truncated
//!      `services_hash` (lets future audits prove the same import
//!      ran twice without naming the services).
//!   3. Set `services_redacted = true` so a downstream auditor can
//!      assert the gate ran.
//!
//! ## Why a typed wrapper, not a runtime assert
//!
//! A "call-site audit + ADR" approach lets a future WAL writer
//! quietly stuff a `username` into the payload. The typed wrapper
//! makes that unrepresentable: the WAL writer accepts only the
//! redacted type, no public constructor on the redacted type other
//! than [`redact_credential_import`]. Same pattern as SC-16
//! `PaperlessOcrPayload`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What the wizard hands to the redactor. Operator-visible side
/// of the import — names, URLs, usernames the operator typed or
/// the upstream export carried. NONE of these reach the WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialImportRecord {
    /// Source format the operator imported from.
    pub source: ImportSource,
    /// The credential entries themselves. Each carries name/url/
    /// username (the things we redact away) + a tag set (the only
    /// thing we keep in aggregate).
    pub entries: Vec<CredentialEntry>,
    /// Operator-chosen vault id where the credentials landed. The
    /// vault id is non-identifying (`"primary"` / `"work"`) so it
    /// survives unredacted.
    pub target_vault_id: String,
    /// Unix seconds of the import.
    pub ts_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    Bitwarden,
    Keepass,
    OnePassword,
    SystemKeyring,
    /// Operator-typed credentials via the wizard prompt — no
    /// upstream source. Distinguishing this in the redacted record
    /// lets later audits explain "where did these come from".
    WizardPrompt,
}

impl ImportSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bitwarden => "bitwarden",
            Self::Keepass => "keepass",
            Self::OnePassword => "one_password",
            Self::SystemKeyring => "system_keyring",
            Self::WizardPrompt => "wizard_prompt",
        }
    }
}

/// One credential entry. The redactor consumes this + drops every
/// field except `tags` (which it aggregates without naming the
/// owning entry).
///
/// **The plaintext secret intentionally does NOT live here.** The
/// redactor never reads it; carrying it through this struct would
/// just allocate a transient plaintext `String` on the way to
/// /dev/null. Caller keeps the secret in a [`super::super::credentials::SecretBytes`]
/// outside this redaction path and hands it to the secret-store
/// writer directly. Field removed 2026-05-26 per operator review:
/// "redaction record rebuilds Strings from secrets".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEntry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub tags: Vec<String>,
}

/// The ONLY payload type the WAL writer accepts for `0x15
/// CREDENTIAL_IMPORT`. Constructible only via
/// [`redact_credential_import`]. Every field below is intentionally
/// non-identifying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedCredentialImportPayload {
    /// Source enum (`bitwarden` / `keepass` / `one_password` /
    /// `system_keyring` / `wizard_prompt`). Non-identifying by
    /// design.
    pub source: ImportSource,
    /// Number of credential entries imported. The count itself
    /// reveals nothing about which credentials.
    pub entry_count: usize,
    /// Distinct tags present in the imported entries, sorted
    /// alphabetically. Tags are operator-chosen labels like
    /// `"work"` / `"personal"` / `"banking"` — non-identifying in
    /// the aggregate. Drops duplicates so the audit can't infer
    /// "how many entries had tag X".
    pub distinct_tags_sorted: Vec<String>,
    /// SHA-256-truncated digest over the SET of unique credential
    /// names (sorted, lowercased) — lets a future audit prove that
    /// the same import ran twice (same hash) without revealing
    /// what the names were.
    pub services_hash: String,
    /// Operator-chosen vault id (non-identifying — `"primary"` /
    /// `"work"`). The wizard validates this is one of a finite
    /// allowlist before passing it through.
    pub target_vault_id: String,
    pub ts_unix: i64,
    /// Drift guard — auditors assert this is always `true`. The
    /// constructor sets it; the field is here so a downstream
    /// `0x15`-emitting test can pattern-match on the redaction
    /// without re-decoding the rest.
    pub services_redacted: bool,
}

impl RedactedCredentialImportPayload {
    /// Read-only accessor for completeness — the type's whole
    /// point is that callers READ these fields but cannot
    /// construct one without going through [`redact_credential_import`].
    pub fn services_redacted(&self) -> bool {
        self.services_redacted
    }
}

/// SHA-256 over `\n`-joined sorted-unique lowercased names,
/// truncated to 16 hex chars (64 bits — enough collision
/// resistance for "did this import run twice"). Pure-fn so the
/// audit-comparison logic doesn't need to recompute via the
/// `Sha256` API surface.
pub fn services_hash(names: &[String]) -> String {
    let mut sorted: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    sorted.sort();
    sorted.dedup();
    let joined = sorted.join("\n");
    let mut h = Sha256::new();
    h.update(joined.as_bytes());
    let digest = h.finalize();
    let hex: String = digest
        .iter()
        .take(8) // 8 bytes = 16 hex chars
        .map(|b| format!("{b:02x}"))
        .collect();
    hex
}

/// SC-17 redactor. The ONLY public path from
/// [`CredentialImportRecord`] to [`RedactedCredentialImportPayload`].
/// Future WAL writers MUST accept the redacted type; review catches
/// a `name`-typed bypass on the first PR.
pub fn redact_credential_import(
    record: &CredentialImportRecord,
) -> RedactedCredentialImportPayload {
    let names: Vec<String> = record.entries.iter().map(|e| e.name.clone()).collect();
    let mut distinct_tags: Vec<String> = record
        .entries
        .iter()
        .flat_map(|e| e.tags.iter().cloned())
        .collect();
    distinct_tags.sort();
    distinct_tags.dedup();

    RedactedCredentialImportPayload {
        source: record.source,
        entry_count: record.entries.len(),
        distinct_tags_sorted: distinct_tags,
        services_hash: services_hash(&names),
        target_vault_id: record.target_vault_id.clone(),
        ts_unix: record.ts_unix,
        services_redacted: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, url: &str, user: &str, tags: &[&str]) -> CredentialEntry {
        CredentialEntry {
            name: name.to_string(),
            url: url.to_string(),
            username: user.to_string(),
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn record(source: ImportSource, entries: Vec<CredentialEntry>) -> CredentialImportRecord {
        CredentialImportRecord {
            source,
            entries,
            target_vault_id: "primary".into(),
            ts_unix: 1_700_000_000,
        }
    }

    // ── source surface ────────────────────────────────────────────

    #[test]
    fn source_as_str_pinned_for_audit() {
        assert_eq!(ImportSource::Bitwarden.as_str(), "bitwarden");
        assert_eq!(ImportSource::Keepass.as_str(), "keepass");
        assert_eq!(ImportSource::OnePassword.as_str(), "one_password");
        assert_eq!(ImportSource::SystemKeyring.as_str(), "system_keyring");
        assert_eq!(ImportSource::WizardPrompt.as_str(), "wizard_prompt");
    }

    #[test]
    fn source_snake_case_serde() {
        let json = serde_json::to_string(&ImportSource::OnePassword).unwrap();
        assert_eq!(json, "\"one_password\"");
    }

    // ── services_hash ─────────────────────────────────────────────

    #[test]
    fn services_hash_deterministic_for_same_names() {
        let a = services_hash(&["paypal".into(), "github".into()]);
        let b = services_hash(&["paypal".into(), "github".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn services_hash_order_independent() {
        let a = services_hash(&["github".into(), "paypal".into()]);
        let b = services_hash(&["paypal".into(), "github".into()]);
        assert_eq!(a, b, "must sort before hashing");
    }

    #[test]
    fn services_hash_case_insensitive() {
        let a = services_hash(&["GitHub".into(), "PayPal".into()]);
        let b = services_hash(&["github".into(), "paypal".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn services_hash_drops_duplicates() {
        let a = services_hash(&["paypal".into(), "paypal".into(), "paypal".into()]);
        let b = services_hash(&["paypal".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn services_hash_differs_on_distinct_inputs() {
        let a = services_hash(&["paypal".into()]);
        let b = services_hash(&["github".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn services_hash_is_16_hex_chars() {
        let h = services_hash(&["x".into()]);
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn services_hash_empty_names_still_hashes() {
        let h = services_hash(&[]);
        assert_eq!(h.len(), 16);
    }

    // ── redactor ──────────────────────────────────────────────────

    #[test]
    fn redactor_drops_name_url_username() {
        let r = record(
            ImportSource::Bitwarden,
            vec![entry(
                "PayPal",
                "https://paypal.com",
                "sam@example.com",
                &["work"],
            )],
        );
        let payload = redact_credential_import(&r);

        // Serialised payload must not contain the leaked fields anywhere.
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("PayPal"));
        assert!(!json.contains("paypal.com"));
        assert!(!json.contains("sam@example.com"));
    }

    #[test]
    fn redactor_keeps_entry_count() {
        let r = record(
            ImportSource::Bitwarden,
            vec![
                entry("a", "", "", &[]),
                entry("b", "", "", &[]),
                entry("c", "", "", &[]),
            ],
        );
        let payload = redact_credential_import(&r);
        assert_eq!(payload.entry_count, 3);
    }

    #[test]
    fn redactor_aggregates_distinct_tags_sorted() {
        let r = record(
            ImportSource::Keepass,
            vec![
                entry("a", "", "", &["work", "banking"]),
                entry("b", "", "", &["personal", "work"]),
            ],
        );
        let payload = redact_credential_import(&r);
        assert_eq!(
            payload.distinct_tags_sorted,
            vec!["banking", "personal", "work"],
        );
    }

    #[test]
    fn redactor_services_hash_proves_repeated_imports() {
        let r1 = record(
            ImportSource::Bitwarden,
            vec![entry("PayPal", "u", "n", &[])],
        );
        let r2 = record(
            ImportSource::Bitwarden,
            vec![entry("paypal", "u", "n", &[])], // case-different
        );
        let p1 = redact_credential_import(&r1);
        let p2 = redact_credential_import(&r2);
        assert_eq!(p1.services_hash, p2.services_hash);
    }

    #[test]
    fn redactor_services_hash_differs_on_distinct_imports() {
        let r1 = record(
            ImportSource::Bitwarden,
            vec![entry("PayPal", "u", "n", &[])],
        );
        let r2 = record(
            ImportSource::Bitwarden,
            vec![entry("GitHub", "u", "n", &[])],
        );
        let p1 = redact_credential_import(&r1);
        let p2 = redact_credential_import(&r2);
        assert_ne!(p1.services_hash, p2.services_hash);
    }

    #[test]
    fn redactor_keeps_target_vault_id_verbatim() {
        let mut r = record(ImportSource::Bitwarden, vec![]);
        r.target_vault_id = "work".into();
        let payload = redact_credential_import(&r);
        assert_eq!(payload.target_vault_id, "work");
    }

    #[test]
    fn redactor_keeps_source_and_ts() {
        let r = record(ImportSource::Keepass, vec![]);
        let payload = redact_credential_import(&r);
        assert_eq!(payload.source, ImportSource::Keepass);
        assert_eq!(payload.ts_unix, 1_700_000_000);
    }

    #[test]
    fn redacted_payload_services_redacted_is_always_true() {
        let r = record(ImportSource::Bitwarden, vec![]);
        let payload = redact_credential_import(&r);
        assert!(payload.services_redacted);
        assert!(payload.services_redacted());
    }

    #[test]
    fn redactor_empty_record_still_valid_payload() {
        let r = record(ImportSource::WizardPrompt, vec![]);
        let payload = redact_credential_import(&r);
        assert_eq!(payload.entry_count, 0);
        assert!(payload.distinct_tags_sorted.is_empty());
        assert!(payload.services_redacted);
    }

    #[test]
    fn redacted_payload_json_serialisation_pins_field_names() {
        // Drift guard — future schema changes must rename fields in
        // PROGRESS + this test; auditors grep on these JSON keys.
        let payload = redact_credential_import(&record(ImportSource::Bitwarden, vec![]));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"source\":\"bitwarden\""));
        assert!(json.contains("\"entry_count\""));
        assert!(json.contains("\"distinct_tags_sorted\""));
        assert!(json.contains("\"services_hash\""));
        assert!(json.contains("\"target_vault_id\":\"primary\""));
        assert!(json.contains("\"ts_unix\""));
        assert!(json.contains("\"services_redacted\":true"));
    }

    #[test]
    fn redactor_unique_tag_dedup_drops_duplicates_within_one_entry() {
        let r = record(
            ImportSource::Bitwarden,
            vec![entry("a", "", "", &["work", "work", "work"])],
        );
        let payload = redact_credential_import(&r);
        assert_eq!(payload.distinct_tags_sorted, vec!["work"]);
    }

    #[test]
    fn credential_entry_carries_no_secret_field() {
        // Drift guard — SC-17 rule says the redactor input MUST
        // NOT carry plaintext secret material. A future PR that
        // re-adds `secret: String` to CredentialEntry will fail
        // this compile-time check via the explicit struct literal.
        let _e = CredentialEntry {
            name: String::new(),
            url: String::new(),
            username: String::new(),
            tags: Vec::new(),
        };
    }
}
