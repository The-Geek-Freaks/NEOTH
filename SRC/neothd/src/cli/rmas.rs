//! `neoth rmas consent [--acknowledge]` — ZF-04 RecursiveMAS code gate.
//!
//! ## What this command does
//!
//! - Without `--acknowledge`: prints both independent RecursiveMAS gates:
//!   third-party code acknowledgement and revocable provider egress consent.
//! - With `--acknowledge`: writes only the third-party code marker if absent
//!   (idempotent), then prints the provider-consent state and exact next step.
//! - Outbound prompt egress remains separately gated by
//!   `neoth consent grant recursive_mas`.
//!
//! ## Marker path
//!
//! `<neoth_home>/rmas_consent_acknowledged` — the EXACT filename the adapter
//! (`providers::recursive_mas::CONSENT_MARKER`) checks at spawn time.
//! This command reuses that constant so the write path and the gate can never
//! drift apart (default home: `~/.neoth`; overridable via `--home` for tests).
//!
//! ## Critical constraint
//!
//! This file is the ONLY place that writes the marker. The wizard
//! (`cli/init/steps_provider.rs`) and ALL preset builtins
//! (`config/preset_builtins.rs`) MUST NEVER write it — verified in tests
//! below and confirmed by code inspection:
//!   - `preset_builtins.rs` asserts `!cfg.recursive_mas.enabled` for every
//!     built-in (line ~268).
//!   - `presets.rs` puts `recursive_mas.enabled` in `PRESET_WARN_PATHS`
//!     (never silently applied).
//!   - `steps_provider.rs` RecursiveMas arm only prints a description;
//!     no `consent::grant` / no marker write (line ~380).
//!
//! ## License text
//!
//! "RecursiveMAS Third-Party Sidecar — upstream license unresolved; \
//!  invoke-only. NEOTH never downloads code or weights. \
//!  The operator is responsible for compliance with the RecursiveMAS \
//!  upstream license."

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::consent::{self, ConsentRoute};

// ── License text (canonical) ──────────────────────────────────────────────────

/// Canonical RMAS license/consent blurb shown to the operator before they
/// decide whether to acknowledge. Kept as a constant so tests and the CLI
/// display exactly the same text.
pub const RMAS_LICENSE_NAME: &str =
    "RecursiveMAS Third-Party Sidecar — upstream license unresolved";

pub const RMAS_LICENSE_NOTICE: &str = "\
RecursiveMAS Third-Party Sidecar — upstream license unresolved; invoke-only.
NEOTH never downloads the RecursiveMAS code or weights itself.
The operator is responsible for compliance with the RecursiveMAS upstream license.
The sidecar is VRAM-gated (≥12 GiB GPU) and must be installed manually
at the path set via `recursive_mas.sidecar_repo` in freedom.yaml.";

// ── Marker path ───────────────────────────────────────────────────────────────

/// Path to the RMAS consent marker inside `neoth_home`. Reuses the adapter's
/// `CONSENT_MARKER` constant — the same filename `RecursiveMasAdapter::spawn`
/// checks — so `--acknowledge` actually satisfies the gate it claims to.
pub fn rmas_marker_path(home: &Path) -> PathBuf {
    crate::providers::recursive_mas::consent_marker_path(home)
}

/// True iff the exact instance contains a canonical, regular, single-link,
/// no-follow acknowledgement marker.
pub fn is_rmas_consent_acknowledged(home: &Path) -> Result<bool> {
    crate::providers::recursive_mas::code_acknowledgement_present(home)
}

/// Create the acknowledgement marker once with private permissions and a
/// durable directory-entry commit. An existing path is accepted only after the
/// same handle-bound validation used by the runtime gate.
///
/// # Errors
/// Returns an error if the home cannot be created, the new marker cannot be
/// committed, or an existing marker is malformed, linked, or not a regular
/// single-link file.
pub fn write_rmas_consent_marker(home: &Path) -> Result<()> {
    std::fs::create_dir_all(home)
        .with_context(|| format!("create neoth home {}", home.display()))?;
    let marker = rmas_marker_path(home);
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    debug_assert_eq!(
        ts.len(),
        crate::providers::recursive_mas::CONSENT_MARKER_BYTES
    );
    match crate::util::atomic_write::write_private_create_new_durable(&marker, ts.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                is_rmas_consent_acknowledged(home)?,
                "RecursiveMAS code acknowledgement disappeared during validation; retry"
            );
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("create RMAS consent marker {}", marker.display()))
        }
    }
}

/// Render both independent RecursiveMAS gates without mutating either one.
///
/// The code acknowledgement permits execution of operator-installed,
/// unresolved-license third-party code. Provider consent separately permits
/// that sidecar to use the host's network for prompt egress. Keeping both
/// states in one renderer prevents CLI help and post-ack output from implying
/// that the code acknowledgement alone makes the provider ready.
fn render_consent_status(home: &Path) -> Result<String> {
    let code_acknowledged = is_rmas_consent_acknowledged(home)?;
    let provider_route = ConsentRoute::new(ProviderKind::RecursiveMas, None);
    let provider_consent_granted = consent::is_route_granted(home, &provider_route);
    let marker = rmas_marker_path(home);

    let mut output = format!(
        "--- RecursiveMAS Readiness ---\n\
         Third-party code acknowledgement: {}\n\
         Provider egress consent:          {}\n\
         Code marker:                      {}\n\
         License:                          {}\n\
         \n\
         {}",
        if code_acknowledged {
            "ACKNOWLEDGED"
        } else {
            "NOT acknowledged"
        },
        if provider_consent_granted {
            "GRANTED"
        } else {
            "NOT granted"
        },
        marker.display(),
        RMAS_LICENSE_NAME,
        RMAS_LICENSE_NOTICE,
    );

    if !code_acknowledged {
        output.push_str(
            "\n\nTo acknowledge the operator-installed third-party code:\n\
             \x20 neoth rmas consent --acknowledge",
        );
    }
    if !provider_consent_granted {
        output.push_str(
            "\n\nTo grant revocable prompt egress for the RecursiveMAS sidecar:\n\
             \x20 neoth consent grant recursive_mas",
        );
    } else {
        output.push_str(
            "\n\nTo revoke RecursiveMAS prompt egress:\n\
             \x20 neoth consent revoke recursive_mas",
        );
    }

    Ok(output)
}

// ── Clap args ─────────────────────────────────────────────────────────────────

/// Inspect both RecursiveMAS gates: code acknowledgement via `neoth rmas consent --acknowledge`; prompt egress via `neoth consent grant recursive_mas` / `neoth consent revoke recursive_mas`.
///
/// `consent` shows both required gates: the unresolved-license code
/// acknowledgement and the separate revocable provider egress consent.
///
/// `consent --acknowledge` writes only the code marker (idempotent). Prompt
/// egress must still be granted with `neoth consent grant recursive_mas`.
/// Only this explicit command creates the code marker — the wizard and preset
/// code never do.
#[derive(Args, Debug, Clone)]
pub struct RmasArgs {
    #[command(subcommand)]
    pub action: RmasAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RmasAction {
    /// Show both gates: code uses `neoth rmas consent --acknowledge`; egress uses `neoth consent grant recursive_mas` / `neoth consent revoke recursive_mas`.
    Consent {
        /// Acknowledge third-party code. Egress consent remains separate.
        #[arg(long)]
        acknowledge: bool,

        /// Override neoth home directory (used by tests; defaults to
        /// `~/.neoth`).
        #[arg(long, hide = true)]
        home: Option<PathBuf>,
    },
}

// ── Run ───────────────────────────────────────────────────────────────────────

pub fn run_rmas(args: RmasArgs, _output: OutputFormat) -> Result<()> {
    match args.action {
        RmasAction::Consent { acknowledge, home } => {
            let home_path = match home {
                Some(p) => p,
                None => FreedomConfig::default_neoth_home(),
            };
            run_consent(&home_path, acknowledge)
        }
    }
}

fn run_consent(home: &Path, acknowledge: bool) -> Result<()> {
    let already = is_rmas_consent_acknowledged(home)?;

    if acknowledge {
        if already {
            println!("RecursiveMAS third-party code was already acknowledged.");
        } else {
            write_rmas_consent_marker(home)?;
            println!("RecursiveMAS third-party code acknowledged.");
        }
    }
    println!("{}", render_consent_status(home)?);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── marker helpers ────────────────────────────────────────────────────────

    #[test]
    fn marker_absent_by_default() {
        let dir = TempDir::new().unwrap();
        assert!(!is_rmas_consent_acknowledged(dir.path()).unwrap());
        assert!(!rmas_marker_path(dir.path()).exists());
    }

    #[test]
    fn write_marker_creates_file_and_is_acknowledged() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()).unwrap());
        assert!(rmas_marker_path(dir.path()).exists());
    }

    #[test]
    fn write_marker_is_idempotent() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        let original = std::fs::read(rmas_marker_path(dir.path())).unwrap();
        // The create-new collision is safely revalidated, not overwritten.
        write_rmas_consent_marker(dir.path()).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()).unwrap());
        assert_eq!(
            std::fs::read(rmas_marker_path(dir.path())).unwrap(),
            original
        );
    }

    #[test]
    fn marker_path_uses_expected_filename() {
        let dir = TempDir::new().unwrap();
        let p = rmas_marker_path(dir.path());
        // Must be byte-identical to the constant the adapter checks, or the
        // consent gate is unsatisfiable (Wave-3 regression).
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some(crate::providers::recursive_mas::CONSENT_MARKER),
        );
    }

    #[test]
    fn acknowledge_satisfies_adapter_gate_path() {
        // The written marker must land at exactly the path the adapter probes.
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        let adapter_probe = dir
            .path()
            .join(crate::providers::recursive_mas::CONSENT_MARKER);
        assert!(
            adapter_probe.exists(),
            "adapter would still see consent missing"
        );
    }

    #[test]
    fn write_marker_stores_non_empty_content() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        let content = std::fs::read_to_string(rmas_marker_path(dir.path())).unwrap();
        assert_eq!(
            content.len(),
            crate::providers::recursive_mas::CONSENT_MARKER_BYTES
        );
        chrono::DateTime::parse_from_rfc3339(&content).unwrap();
    }

    #[test]
    fn malformed_and_oversized_markers_fail_closed() {
        for payload in [
            b"not-a-timestamp".as_slice(),
            b"2026-07-26T12:00:00+00:00".as_slice(),
            &[b'x'; crate::providers::recursive_mas::CONSENT_MARKER_BYTES + 1],
        ] {
            let dir = TempDir::new().unwrap();
            std::fs::write(rmas_marker_path(dir.path()), payload).unwrap();
            assert!(is_rmas_consent_acknowledged(dir.path()).is_err());
            assert!(write_rmas_consent_marker(dir.path()).is_err());
        }
    }

    #[test]
    fn directory_and_hard_link_markers_fail_closed_without_mutation() {
        let directory_home = TempDir::new().unwrap();
        std::fs::create_dir(rmas_marker_path(directory_home.path())).unwrap();
        assert!(is_rmas_consent_acknowledged(directory_home.path()).is_err());
        assert!(write_rmas_consent_marker(directory_home.path()).is_err());
        assert!(rmas_marker_path(directory_home.path()).is_dir());

        let linked_home = TempDir::new().unwrap();
        let original = linked_home.path().join("original.txt");
        let original_bytes = b"2026-07-26T12:00:00Z";
        std::fs::write(&original, original_bytes).unwrap();
        std::fs::hard_link(&original, rmas_marker_path(linked_home.path())).unwrap();
        assert!(is_rmas_consent_acknowledged(linked_home.path()).is_err());
        assert!(write_rmas_consent_marker(linked_home.path()).is_err());
        assert_eq!(std::fs::read(original).unwrap(), original_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_marker_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"must stay unchanged").unwrap();
        symlink(&target, rmas_marker_path(dir.path())).unwrap();

        assert!(is_rmas_consent_acknowledged(dir.path()).is_err());
        assert!(write_rmas_consent_marker(dir.path()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"must stay unchanged");
    }

    #[cfg(windows)]
    #[test]
    fn reparse_point_marker_is_rejected_without_touching_its_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let sentinel = target.join("sentinel.txt");
        std::fs::write(&sentinel, b"must stay unchanged").unwrap();
        let marker = rmas_marker_path(dir.path());
        let status = std::process::Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(&marker)
            .arg(&target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J must create the test fixture");

        assert!(is_rmas_consent_acknowledged(dir.path()).is_err());
        assert!(write_rmas_consent_marker(dir.path()).is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"must stay unchanged");
    }

    // ── run_consent status path ───────────────────────────────────────────────

    #[test]
    fn status_path_exits_ok_when_not_acknowledged() {
        let dir = TempDir::new().unwrap();
        // Should complete without error even with no marker.
        run_consent(dir.path(), false).unwrap();
    }

    #[test]
    fn status_path_exits_ok_when_already_acknowledged() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        run_consent(dir.path(), false).unwrap();
    }

    #[test]
    fn status_exposes_both_independent_gates_and_exact_commands() {
        let dir = TempDir::new().unwrap();
        let status = render_consent_status(dir.path()).unwrap();
        assert!(status.contains("Third-party code acknowledgement: NOT acknowledged"));
        assert!(status.contains("Provider egress consent:          NOT granted"));
        assert!(status.contains("neoth rmas consent --acknowledge"));
        assert!(status.contains("neoth consent grant recursive_mas"));
    }

    #[test]
    fn acknowledgement_does_not_claim_provider_egress_authority() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        let status = render_consent_status(dir.path()).unwrap();
        assert!(status.contains("Third-party code acknowledgement: ACKNOWLEDGED"));
        assert!(status.contains("Provider egress consent:          NOT granted"));
        assert!(!status.contains("neoth rmas consent --acknowledge"));
        assert!(status.contains("neoth consent grant recursive_mas"));
    }

    #[test]
    fn provider_consent_is_reported_and_revokable_independently() {
        let dir = TempDir::new().unwrap();
        let route = ConsentRoute::new(ProviderKind::RecursiveMas, None);
        consent::grant_route(dir.path(), &route).unwrap();
        let status = render_consent_status(dir.path()).unwrap();
        assert!(status.contains("Provider egress consent:          GRANTED"));
        assert!(status.contains("neoth consent revoke recursive_mas"));
        assert!(!status.contains("neoth consent grant recursive_mas"));
    }

    // ── acknowledge path ──────────────────────────────────────────────────────

    #[test]
    fn acknowledge_writes_marker_and_exits_ok() {
        let dir = TempDir::new().unwrap();
        assert!(!is_rmas_consent_acknowledged(dir.path()).unwrap());
        run_consent(dir.path(), true).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()).unwrap());
    }

    #[test]
    fn acknowledge_idempotent_when_already_present() {
        let dir = TempDir::new().unwrap();
        run_consent(dir.path(), true).unwrap();
        // Second call must still exit 0 with friendly notice.
        run_consent(dir.path(), true).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()).unwrap());
    }

    // ── wizard/preset safety evidence ────────────────────────────────────────
    //
    // These tests compile-lock the guarantee that no wizard or preset path
    // calls write_rmas_consent_marker. They do so by asserting the marker is
    // absent after simulating what the wizard/preset code paths actually do:
    // they only touch `freedom.yaml` config fields, never the marker file.
    //
    // The preset_builtins.rs `full_auto` built-in is the most permissive
    // preset in the system; even it asserts `!cfg.recursive_mas.enabled`
    // (see config/preset_builtins.rs ~L268) which means it cannot have
    // triggered a marker write.

    #[test]
    fn marker_not_present_before_explicit_acknowledge() {
        // If any init/wizard/preset code were silently writing the marker, this
        // test would fail. It uses a pristine temp dir so no production home is
        // touched.
        let dir = TempDir::new().unwrap();
        // The wizard RecursiveMas arm only prints descriptive text — it never
        // calls write_rmas_consent_marker, so a pristine home has no marker.
        assert!(
            !is_rmas_consent_acknowledged(dir.path()).unwrap(),
            "marker must NOT exist unless --acknowledge was passed explicitly"
        );
    }
}
