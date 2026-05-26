//! W-08 — typed payload structs for the wizard / install / credential
//! event frames.
//!
//! Pinned shapes so a future WAL reader can rely on the field names
//! without re-deriving them from emit-site source code. Each
//! struct serialises to the exact JSON shape the corresponding
//! `EVENT_TYPE_*` constant in [`super::events`] documents.
//!
//! ## Why typed + tested + not just docs
//!
//! The W-08 spec listed payload fields in a docstring. That's a
//! contract the linter can't enforce — emit sites drift, tests
//! grep for old field names, audit consumers parse the wrong
//! shape. Typed structs + serde + per-field snake_case rename
//! make the wire form unrepresentable to break without a PR-level
//! review.

use serde::{Deserialize, Serialize};

use crate::installers::detect::DetectReport;
use crate::installers::gpu::GpuKind;
use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};

/// `0xD5 DETECT_COMPLETE` payload — emit one frame per wizard
/// detect-step completion. Mirrors `DetectReport` but with all
/// optional probes flattened to either `None` or `Some(value)` —
/// auditors can `WHERE docker_version IS NOT NULL` cleanly.
///
/// `gpu` lifts the nested `GpuReport` into top-level fields so the
/// audit-side `WHERE gpu_kind = 'cuda' AND vram_mib >= 24576`
/// queries stay flat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectCompletePayload {
    pub probed_at_unix: u64,
    #[serde(default)]
    pub docker_version: Option<String>,
    #[serde(default)]
    pub docker_compose_version: Option<String>,
    #[serde(default)]
    pub docker_compose_legacy_version: Option<String>,
    #[serde(default)]
    pub npm_version: Option<String>,
    #[serde(default)]
    pub node_version: Option<String>,
    #[serde(default)]
    pub git_version: Option<String>,
    #[serde(default)]
    pub ffmpeg_version: Option<String>,
    /// Snake_case audit tag of the GPU kind. `None` when no GPU
    /// detected (Cpu fallback). Pinned tags: `cuda` / `rocm` /
    /// `metal` / `cpu`.
    #[serde(default)]
    pub gpu_kind: Option<String>,
    #[serde(default)]
    pub gpu_vram_mib: Option<u32>,
    #[serde(default)]
    pub gpu_vendor: Option<String>,
    #[serde(default)]
    pub gpu_name: Option<String>,
    #[serde(default)]
    pub disk_free_bytes: Option<u64>,
}

impl DetectCompletePayload {
    /// Project a `DetectReport` (the wizard-side rich type) into
    /// the audit-flat payload. Lossless for the canonical fields.
    pub fn from_report(report: &DetectReport) -> Self {
        let (gpu_kind, gpu_vram_mib, gpu_vendor, gpu_name) = match &report.gpu {
            None => (None, None, None, None),
            Some(g) => (
                Some(g.kind.as_str().to_string()),
                g.vram_mib,
                g.vendor.clone(),
                g.name.clone(),
            ),
        };
        Self {
            probed_at_unix: report.probed_at_unix,
            docker_version: report.docker_version.clone(),
            docker_compose_version: report.docker_compose_version.clone(),
            docker_compose_legacy_version: report.docker_compose_legacy_version.clone(),
            npm_version: report.npm_version.clone(),
            node_version: report.node_version.clone(),
            git_version: report.git_version.clone(),
            ffmpeg_version: report.ffmpeg_version.clone(),
            gpu_kind,
            gpu_vram_mib,
            gpu_vendor,
            gpu_name,
            disk_free_bytes: report.disk_free_bytes,
        }
    }

    /// True when the report indicates an accelerator-class GPU was
    /// detected. Audit shorthand — `WHERE has_accelerator`.
    pub fn has_accelerator(&self) -> bool {
        matches!(self.gpu_kind.as_deref(), Some(s) if s != GpuKind::Cpu.as_str())
    }
}

/// `0x12 INSTALLER_RAN` extended payload (W-08).
///
/// Existing fields (`cli_name`, `version`, `login_state`,
/// `ts_unix`) kept verbatim; W-08 adds:
///
///   - `dry_run`: true when the wizard step was operator-confirmed
///     but NEOTH printed-not-spawned the command.
///   - `wizard_step`: which wizard step fired the install (a
///     pinned string like `"step5_cli_picker"` so different steps
///     installing the same CLI are distinguishable).
///   - `pkg_mgr`: which package manager carried the install
///     (`"winget"` / `"choco"` / `"apt"` / `"dnf"` / `"pacman"` /
///     `"brew"` / `"npm"` / `"manual"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallerRanPayload {
    pub cli_name: String,
    pub version: String,
    pub login_state: String,
    pub ts_unix: u64,
    /// W-08 addition: true when the wizard printed the command +
    /// asked the operator to run it themselves (no subprocess
    /// spawn). False = NEOTH actually ran the install.
    #[serde(default)]
    pub dry_run: bool,
    /// W-08 addition: pinned wizard-step identifier so re-runs of
    /// the same CLI from different steps are distinguishable.
    /// Empty when the install fired outside a wizard step (e.g.
    /// `neoth update --apply`).
    #[serde(default)]
    pub wizard_step: String,
    /// W-08 addition: package manager that carried the install.
    /// Empty when the install bypassed a known package manager
    /// (manual binary download, etc).
    #[serde(default)]
    pub pkg_mgr: String,
}

impl InstallerRanPayload {
    /// Constructor with the W-08 fields zeroed — call this from
    /// non-wizard contexts where dry_run / wizard_step / pkg_mgr
    /// don't apply. The Default values stay serde-stable.
    pub fn legacy(
        cli_name: impl Into<String>,
        version: impl Into<String>,
        login_state: impl Into<String>,
        ts_unix: u64,
    ) -> Self {
        Self {
            cli_name: cli_name.into(),
            version: version.into(),
            login_state: login_state.into(),
            ts_unix,
            dry_run: false,
            wizard_step: String::new(),
            pkg_mgr: String::new(),
        }
    }
}

/// `0xD6 CREDENTIAL_IMPORT` payload — same shape as
/// [`RedactedCredentialImportPayload`] (SC-17). Re-exported here
/// under the W-08 module so audit consumers can `use
/// wal::payloads_w08::CredentialImportPayload` without reaching
/// into the `security::` namespace.
pub type CredentialImportPayload = RedactedCredentialImportPayload;

/// Operator-facing assertion used by audit tooling: every
/// `0xD6 CREDENTIAL_IMPORT` payload MUST have
/// `services_redacted == true`. SC-17 hard rule.
pub fn audit_credential_import_redacted(payload: &CredentialImportPayload) -> bool {
    payload.services_redacted
}

/// Convenience: snake_case audit tag for an ImportSource, matching
/// what serde emits.
pub fn source_audit_tag(source: ImportSource) -> &'static str {
    source.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::detect::DetectReport;
    use crate::installers::gpu::{GpuKind, GpuReport};
    use crate::security::credential_redact::{
        CredentialImportRecord, ImportSource, redact_credential_import,
    };

    fn fresh_report(ts: u64) -> DetectReport {
        DetectReport {
            probed_at_unix: ts,
            docker_version: Some("Docker 25.0.0".into()),
            docker_compose_version: Some("Compose v2.24".into()),
            docker_compose_legacy_version: None,
            npm_version: Some("10.2.0".into()),
            node_version: Some("v20.10.0".into()),
            git_version: Some("git 2.42".into()),
            ffmpeg_version: None,
            gpu: Some(GpuReport {
                kind: GpuKind::Cuda,
                vram_mib: Some(24_000),
                vendor: Some("NVIDIA".into()),
                name: Some("RTX 4090".into()),
            }),
            disk_free_bytes: Some(500 * 1024 * 1024 * 1024),
        }
    }

    // ── DetectCompletePayload ─────────────────────────────────────

    #[test]
    fn detect_complete_from_report_carries_every_field() {
        let r = fresh_report(1_700_000_000);
        let p = DetectCompletePayload::from_report(&r);
        assert_eq!(p.probed_at_unix, 1_700_000_000);
        assert_eq!(p.docker_version.as_deref(), Some("Docker 25.0.0"));
        assert_eq!(p.docker_compose_version.as_deref(), Some("Compose v2.24"));
        assert!(p.docker_compose_legacy_version.is_none());
        assert_eq!(p.npm_version.as_deref(), Some("10.2.0"));
        assert_eq!(p.node_version.as_deref(), Some("v20.10.0"));
        assert_eq!(p.git_version.as_deref(), Some("git 2.42"));
        assert!(p.ffmpeg_version.is_none());
        assert_eq!(p.gpu_kind.as_deref(), Some("cuda"));
        assert_eq!(p.gpu_vram_mib, Some(24_000));
        assert_eq!(p.gpu_vendor.as_deref(), Some("NVIDIA"));
        assert_eq!(p.gpu_name.as_deref(), Some("RTX 4090"));
        assert_eq!(p.disk_free_bytes, Some(500 * 1024 * 1024 * 1024));
    }

    #[test]
    fn detect_complete_no_gpu_zeros_gpu_fields() {
        let mut r = fresh_report(0);
        r.gpu = None;
        let p = DetectCompletePayload::from_report(&r);
        assert!(p.gpu_kind.is_none());
        assert!(p.gpu_vram_mib.is_none());
        assert!(p.gpu_vendor.is_none());
        assert!(p.gpu_name.is_none());
    }

    #[test]
    fn detect_complete_cpu_kind_has_accelerator_false() {
        let mut r = fresh_report(0);
        r.gpu = Some(GpuReport::cpu());
        let p = DetectCompletePayload::from_report(&r);
        assert!(!p.has_accelerator());
    }

    #[test]
    fn detect_complete_cuda_kind_has_accelerator_true() {
        let p = DetectCompletePayload::from_report(&fresh_report(0));
        assert!(p.has_accelerator());
    }

    #[test]
    fn detect_complete_no_gpu_has_accelerator_false() {
        let mut r = fresh_report(0);
        r.gpu = None;
        let p = DetectCompletePayload::from_report(&r);
        assert!(!p.has_accelerator());
    }

    #[test]
    fn detect_complete_serialises_snake_case_fields() {
        let p = DetectCompletePayload::from_report(&fresh_report(42));
        let json = serde_json::to_string(&p).unwrap();
        // Audit consumers grep for these exact keys.
        for key in [
            "probed_at_unix",
            "docker_version",
            "docker_compose_version",
            "docker_compose_legacy_version",
            "npm_version",
            "node_version",
            "git_version",
            "ffmpeg_version",
            "gpu_kind",
            "gpu_vram_mib",
            "gpu_vendor",
            "gpu_name",
            "disk_free_bytes",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing key {key} in {json}",
            );
        }
        assert!(json.contains("\"gpu_kind\":\"cuda\""));
    }

    #[test]
    fn detect_complete_serde_roundtrip() {
        let p = DetectCompletePayload::from_report(&fresh_report(99));
        let json = serde_json::to_string(&p).unwrap();
        let back: DetectCompletePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    // ── InstallerRanPayload ───────────────────────────────────────

    #[test]
    fn installer_ran_legacy_constructor_zeros_w08_fields() {
        let p = InstallerRanPayload::legacy("claude-cli", "1.2.3", "logged_in", 100);
        assert_eq!(p.cli_name, "claude-cli");
        assert!(!p.dry_run);
        assert!(p.wizard_step.is_empty());
        assert!(p.pkg_mgr.is_empty());
    }

    #[test]
    fn installer_ran_serialises_all_fields() {
        let p = InstallerRanPayload {
            cli_name: "claude-cli".into(),
            version: "1.2.3".into(),
            login_state: "logged_in".into(),
            ts_unix: 100,
            dry_run: true,
            wizard_step: "step5_cli_picker".into(),
            pkg_mgr: "winget".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        for key in [
            "cli_name",
            "version",
            "login_state",
            "ts_unix",
            "dry_run",
            "wizard_step",
            "pkg_mgr",
        ] {
            assert!(json.contains(&format!("\"{key}\"")), "missing key {key}",);
        }
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"wizard_step\":\"step5_cli_picker\""));
        assert!(json.contains("\"pkg_mgr\":\"winget\""));
    }

    #[test]
    fn installer_ran_back_compat_payload_with_missing_w08_fields_deserialises() {
        // Old payload that pre-dates W-08 (no dry_run/wizard_step/
        // pkg_mgr) MUST still parse, with the W-08 fields defaulted.
        let json = r#"{
            "cli_name":"claude-cli",
            "version":"1.2.3",
            "login_state":"logged_in",
            "ts_unix":100
        }"#;
        let p: InstallerRanPayload = serde_json::from_str(json).unwrap();
        assert!(!p.dry_run);
        assert!(p.wizard_step.is_empty());
        assert!(p.pkg_mgr.is_empty());
    }

    #[test]
    fn installer_ran_serde_roundtrip() {
        let p = InstallerRanPayload {
            cli_name: "codex".into(),
            version: "0.5.0".into(),
            login_state: "anonymous".into(),
            ts_unix: 200,
            dry_run: false,
            wizard_step: "step5_cli_picker".into(),
            pkg_mgr: "npm".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: InstallerRanPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    // ── CredentialImportPayload re-export ─────────────────────────

    #[test]
    fn credential_import_payload_is_redacted_alias() {
        let record = CredentialImportRecord {
            source: ImportSource::Bitwarden,
            entries: vec![],
            target_vault_id: "primary".into(),
            ts_unix: 1_700_000_000,
        };
        let payload = redact_credential_import(&record);
        // The W-08 module's type alias resolves to the same struct.
        let _: CredentialImportPayload = payload.clone();
        // The audit invariant fn returns true.
        assert!(audit_credential_import_redacted(&payload));
    }

    #[test]
    fn audit_credential_import_redacted_pins_sc17_invariant() {
        // Build a payload where services_redacted is forced false
        // (would only happen if a malicious caller hand-crafted it
        // — impossible via the public API). The audit fn correctly
        // returns false in that synthetic case.
        let mut payload = redact_credential_import(&CredentialImportRecord {
            source: ImportSource::Bitwarden,
            entries: vec![],
            target_vault_id: "primary".into(),
            ts_unix: 0,
        });
        payload.services_redacted = false;
        assert!(!audit_credential_import_redacted(&payload));
    }

    #[test]
    fn source_audit_tag_matches_import_source_as_str() {
        for src in [
            ImportSource::Bitwarden,
            ImportSource::Keepass,
            ImportSource::OnePassword,
            ImportSource::SystemKeyring,
            ImportSource::WizardPrompt,
        ] {
            assert_eq!(source_audit_tag(src), src.as_str());
        }
    }
}
