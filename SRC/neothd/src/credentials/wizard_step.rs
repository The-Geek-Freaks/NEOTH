//! C-05 — wizard step + settings-panel parity for the
//! credentials import flow.
//!
//! The wizard's step-6 (credential import) and the GUI settings
//! panel both consume this module's pure-data primitives so the
//! two surfaces stay in lockstep — same operator picks, same
//! consent UI, same WAL frame. A5 SC-17 invariant is encoded in
//! the type system: every payload that reaches the WAL goes
//! through the redactor.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::credentials::bitwarden::BitwardenJsonImporter;
// GOLD-SEC-18: browser importers only exist with the `browser-import` feature.
#[cfg(feature = "browser-import")]
use crate::credentials::chrome::ChromeImporter;
#[cfg(feature = "browser-import")]
use crate::credentials::firefox::FirefoxImporter;
use crate::credentials::{CredentialImporter, ImportSession, ImporterOutcome, build_import_record};
use crate::secret::SecretString;
use crate::security::credential_redact::{
    RedactedCredentialImportPayload, redact_credential_import,
};

/// One operator-visible importer entry the wizard step picker
/// renders. Constructed once at step-entry from the available
/// importer list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardImporterEntry {
    /// Stable id the wizard's settings-panel pairs with this
    /// entry. Snake_case.
    pub id: String,
    /// Operator-facing name (from `CredentialImporter::name()`).
    pub name: String,
    /// True when the source is present on this host. Wizard
    /// greys out unavailable entries instead of hiding them so
    /// operators know what's there.
    pub available: bool,
}

/// Per-importer wizard outcome — same shape as
/// [`super::ImporterOutcome`] minus the secret-bearing entries
/// (the wizard view only needs counts + warnings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardImportOutcomeSummary {
    pub importer_id: String,
    pub importer_name: String,
    pub ok: bool,
    pub entry_count: usize,
    pub warning_count: usize,
    /// Up to first 5 warnings, surface to operator in the UI.
    pub warning_preview: Vec<String>,
    /// First-line of the error when `ok == false`. Empty on success.
    pub error_summary: String,
}

impl WizardImportOutcomeSummary {
    pub fn from_outcome(outcome: &ImporterOutcome) -> Self {
        let importer_id = importer_id_for_source(outcome.source);
        match &outcome.result {
            Ok(d) => Self {
                importer_id,
                importer_name: outcome.name.clone(),
                ok: true,
                entry_count: d.entries.len(),
                warning_count: d.warnings.len(),
                warning_preview: d.warnings.iter().take(5).cloned().collect(),
                error_summary: String::new(),
            },
            Err(e) => Self {
                importer_id,
                importer_name: outcome.name.clone(),
                ok: false,
                entry_count: 0,
                warning_count: 0,
                warning_preview: Vec::new(),
                error_summary: e.lines().next().unwrap_or("").to_string(),
            },
        }
    }
}

/// Map an `ImportSource` to a stable snake_case id the wizard's
/// settings-panel grep-matches against.
pub fn importer_id_for_source(source: super::ImportSource) -> String {
    source.as_str().to_string()
}

/// Build the static importer list the wizard picker renders.
/// `bitwarden_export_path` is operator-supplied via the wizard
/// prompt (None = Bitwarden entry hidden in the picker).
/// `bitwarden_password` (C-02b) is attached when the operator's export
/// is the password-protected variant; the importer auto-detects the
/// format at discover-time, so a `None` password with a plaintext export
/// is the common case, and a `None` password with an encrypted export
/// surfaces a clear error rather than a silent empty vault.
pub fn build_wizard_importer_list(
    bitwarden_export_path: Option<&Path>,
    bitwarden_password: Option<SecretString>,
) -> Vec<Box<dyn CredentialImporter>> {
    let mut out: Vec<Box<dyn CredentialImporter>> = Vec::new();
    if let Some(path) = bitwarden_export_path {
        let mut importer = BitwardenJsonImporter::new(path);
        if let Some(password) = bitwarden_password {
            importer = importer.with_password(password);
        }
        out.push(Box::new(importer));
    }
    // GOLD-SEC-18: the Chrome + Firefox importers are compiled in only with the
    // `browser-import` feature (OFF by default + in release). Without it the
    // wizard's credential-import step offers only the Bitwarden-export path.
    #[cfg(feature = "browser-import")]
    {
        out.push(Box::new(ChromeImporter));
        // C-04b Phase 2 chunk 3 (Session 28) — the Firefox importer
        // now carries the operator's primary password. The wizard's
        // step-6 default path constructs with no-primary-password (the
        // vast-majority install case); the interactive prompt branch
        // calls `FirefoxImporter::new(SecretString::new(prompt))` when
        // the operator has a primary password set. The non-interactive
        // path always uses `with_no_primary_password()` — operators
        // with a primary-password-protected profile must use the
        // interactive wizard or rerun with a future SC-flagged env-var.
        out.push(Box::new(FirefoxImporter::with_no_primary_password()));
    }
    out
}

/// Aggregate every importer outcome into the SC-17-redacted WAL
/// payload + the wizard-UI summary list. Caller emits the
/// payload as `0xD6 CREDENTIAL_IMPORT`. The summary list goes to
/// the wizard's "what we imported" page.
pub async fn run_wizard_step(
    importers: Vec<Box<dyn CredentialImporter>>,
    target_vault_id: impl Into<String>,
    ts_unix: i64,
) -> WizardImportStepResult {
    let session = ImportSession::new(importers);
    let outcomes = session.run().await;
    let summaries: Vec<WizardImportOutcomeSummary> = outcomes
        .iter()
        .map(WizardImportOutcomeSummary::from_outcome)
        .collect();
    let record = build_import_record(&outcomes, target_vault_id, ts_unix);
    let redacted_payload = redact_credential_import(&record);
    WizardImportStepResult {
        summaries,
        redacted_payload,
    }
}

/// Full result of one wizard import step. The
/// `redacted_payload.services_redacted` invariant is `true` by
/// construction (SC-17 hard rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardImportStepResult {
    pub summaries: Vec<WizardImportOutcomeSummary>,
    pub redacted_payload: RedactedCredentialImportPayload,
}

impl WizardImportStepResult {
    /// True when at least one importer ran cleanly (regardless of
    /// whether it found entries). The wizard branches on this to
    /// decide whether to show "import done" vs "no source
    /// available".
    pub fn any_importer_succeeded(&self) -> bool {
        self.summaries.iter().any(|s| s.ok)
    }

    /// Total credentials across all successful importers.
    pub fn total_entries(&self) -> usize {
        self.summaries
            .iter()
            .filter(|s| s.ok)
            .map(|s| s.entry_count)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::ImportSource;

    // ── importer_id_for_source ────────────────────────────────────

    #[test]
    fn importer_id_matches_source_as_str() {
        assert_eq!(importer_id_for_source(ImportSource::Bitwarden), "bitwarden");
        assert_eq!(importer_id_for_source(ImportSource::Keepass), "keepass");
        assert_eq!(
            importer_id_for_source(ImportSource::OnePassword),
            "one_password",
        );
        assert_eq!(
            importer_id_for_source(ImportSource::SystemKeyring),
            "system_keyring",
        );
        assert_eq!(
            importer_id_for_source(ImportSource::WizardPrompt),
            "wizard_prompt",
        );
    }

    // ── build_wizard_importer_list ────────────────────────────────

    /// Number of browser importers (Chrome + Firefox) the list carries —
    /// 2 with the `browser-import` feature, 0 without (GOLD-SEC-18).
    #[cfg(feature = "browser-import")]
    const BROWSER_IMPORTERS: usize = 2;
    #[cfg(not(feature = "browser-import"))]
    const BROWSER_IMPORTERS: usize = 0;

    #[test]
    fn build_list_without_bitwarden_path_has_browser_importers_only_when_gated() {
        let list = build_wizard_importer_list(None, None);
        assert_eq!(list.len(), BROWSER_IMPORTERS);
        // Both chrome + firefox importers are WizardPrompt source (their gated
        // impls); with the feature off the list is simply empty.
        for imp in &list {
            assert_eq!(imp.source(), ImportSource::WizardPrompt);
        }
    }

    #[test]
    fn build_list_with_bitwarden_path_adds_it_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(&path, "{}").unwrap();
        let list = build_wizard_importer_list(Some(&path), None);
        assert_eq!(list.len(), 1 + BROWSER_IMPORTERS);
        // Bitwarden lands first.
        assert_eq!(list[0].source(), ImportSource::Bitwarden);
    }

    // ── run_wizard_step ───────────────────────────────────────────

    #[tokio::test]
    async fn wizard_step_with_no_available_importer_redacts_payload_empty() {
        let result = run_wizard_step(build_wizard_importer_list(None, None), "primary", 100).await;
        assert!(result.redacted_payload.services_redacted);
        assert_eq!(result.redacted_payload.target_vault_id, "primary");
        assert_eq!(result.redacted_payload.ts_unix, 100);
    }

    #[tokio::test]
    async fn wizard_step_with_bitwarden_export_runs_through_redactor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        let body = r#"{
            "folders":[],
            "items":[{
                "name":"PayPal","type":1,
                "login":{"username":"sam","password":"supersecret","uris":[{"uri":"https://paypal.com"}]}
            }]
        }"#;
        std::fs::write(&path, body).unwrap();
        let result = run_wizard_step(
            build_wizard_importer_list(Some(&path), None),
            "primary",
            1_700_000_000,
        )
        .await;

        let json = serde_json::to_string(&result.redacted_payload).unwrap();
        assert!(!json.contains("PayPal"));
        assert!(!json.contains("sam"));
        assert!(!json.contains("supersecret"));
        assert!(result.redacted_payload.services_redacted);
        assert_eq!(result.redacted_payload.entry_count, 1);
    }

    #[tokio::test]
    async fn wizard_step_encrypted_export_without_password_reports_clear_error() {
        // C-02b end-to-end: an encrypted export handed to the wizard with
        // no password must surface a failed Bitwarden outcome with an
        // actionable error — NOT a silently-successful empty import.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(&path, r#"{"encrypted":true,"data":"2.a|b|c"}"#).unwrap();
        let result =
            run_wizard_step(build_wizard_importer_list(Some(&path), None), "primary", 0).await;
        let bw = result
            .summaries
            .iter()
            .find(|s| s.importer_name.contains("Bitwarden"))
            .expect("bitwarden summary present");
        assert!(
            !bw.ok,
            "encrypted export with no password must fail, not silently succeed"
        );
        assert!(
            bw.error_summary.contains("encrypted") || bw.error_summary.contains("password"),
            "error must be actionable, got: {}",
            bw.error_summary
        );
    }

    #[tokio::test]
    async fn wizard_step_any_importer_succeeded_true_when_at_least_one_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(&path, "{}").unwrap();
        let result =
            run_wizard_step(build_wizard_importer_list(Some(&path), None), "primary", 0).await;
        assert!(result.any_importer_succeeded());
    }

    #[tokio::test]
    async fn wizard_step_total_entries_sums_across_successful_importers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        let body = r#"{"items":[
            {"name":"a","type":1,"login":{"username":"u","password":"p","uris":[{"uri":"x"}]}},
            {"name":"b","type":1,"login":{"username":"u","password":"p","uris":[{"uri":"y"}]}}
        ]}"#;
        std::fs::write(&path, body).unwrap();
        let result =
            run_wizard_step(build_wizard_importer_list(Some(&path), None), "primary", 0).await;
        assert_eq!(result.total_entries(), 2);
    }

    // ── WizardImportOutcomeSummary projection ─────────────────────

    #[test]
    fn summary_from_ok_outcome_carries_counts() {
        use crate::credentials::DiscoveredCredentials;
        let outcome = ImporterOutcome {
            source: ImportSource::Bitwarden,
            name: "Bitwarden".to_string(),
            result: Ok(DiscoveredCredentials {
                source: ImportSource::Bitwarden,
                entries: Vec::new(),
                warnings: vec!["a".into(), "b".into(), "c".into()],
            }),
        };
        let s = WizardImportOutcomeSummary::from_outcome(&outcome);
        assert!(s.ok);
        assert_eq!(s.importer_id, "bitwarden");
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.warning_count, 3);
        assert_eq!(s.warning_preview.len(), 3);
        assert!(s.error_summary.is_empty());
    }

    #[test]
    fn summary_warning_preview_caps_at_5() {
        use crate::credentials::DiscoveredCredentials;
        let outcome = ImporterOutcome {
            source: ImportSource::Bitwarden,
            name: "Bitwarden".to_string(),
            result: Ok(DiscoveredCredentials {
                source: ImportSource::Bitwarden,
                entries: Vec::new(),
                warnings: (0..10).map(|i| format!("warn {i}")).collect(),
            }),
        };
        let s = WizardImportOutcomeSummary::from_outcome(&outcome);
        assert_eq!(s.warning_count, 10);
        assert_eq!(s.warning_preview.len(), 5);
    }

    #[test]
    fn summary_from_err_outcome_captures_first_line() {
        let outcome = ImporterOutcome {
            source: ImportSource::Bitwarden,
            name: "Bitwarden".to_string(),
            result: Err("first line\nsecond line\nthird".to_string()),
        };
        let s = WizardImportOutcomeSummary::from_outcome(&outcome);
        assert!(!s.ok);
        assert_eq!(s.error_summary, "first line");
        assert_eq!(s.entry_count, 0);
    }

    #[test]
    fn summary_serialises_snake_case_keys() {
        let s = WizardImportOutcomeSummary {
            importer_id: "bitwarden".into(),
            importer_name: "Bitwarden".into(),
            ok: true,
            entry_count: 5,
            warning_count: 2,
            warning_preview: vec!["w1".into()],
            error_summary: String::new(),
        };
        let json = serde_json::to_string(&s).unwrap();
        for key in [
            "importer_id",
            "importer_name",
            "ok",
            "entry_count",
            "warning_count",
            "warning_preview",
            "error_summary",
        ] {
            assert!(json.contains(&format!("\"{key}\"")), "missing key {key}");
        }
    }
}
