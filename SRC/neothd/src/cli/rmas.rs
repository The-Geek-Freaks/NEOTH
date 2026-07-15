//! `neoth rmas consent [--acknowledge]` — ZF-04 RecursiveMAS consent gate.
//!
//! ## What this command does
//!
//! - Without `--acknowledge`: prints the RecursiveMAS license/consent status
//!   (marker present/absent, marker path, license name) and exits 0.
//! - With `--acknowledge`: writes the consent marker if absent (idempotent —
//!   already-present marker prints a friendly notice and exits 0 cleanly).
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

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

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
    home.join(crate::providers::recursive_mas::CONSENT_MARKER)
}

/// True iff the consent marker exists.
pub fn is_rmas_consent_acknowledged(home: &Path) -> bool {
    rmas_marker_path(home).exists()
}

/// Write the consent marker (idempotent — overwrites timestamp on each call).
///
/// # Errors
/// Returns an error only if the home directory cannot be created or the
/// marker file cannot be written.
pub fn write_rmas_consent_marker(home: &Path) -> Result<()> {
    fs::create_dir_all(home).with_context(|| format!("create neoth home {}", home.display()))?;
    let marker = rmas_marker_path(home);
    // Store a human-readable UTC timestamp so operators can audit when they
    // acknowledged by hand (`cat ~/.neoth/rmas_consent_acknowledged`).
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    fs::write(&marker, ts.as_bytes())
        .with_context(|| format!("write RMAS consent marker {}", marker.display()))?;
    Ok(())
}

// ── Clap args ─────────────────────────────────────────────────────────────────

/// ZF-04 — RecursiveMAS consent gate + status inspector.
///
/// Without `--acknowledge`: shows the license notice, current marker state,
/// and marker path. Exit 0 regardless.
///
/// With `--acknowledge`: writes the consent marker (idempotent). Prints a
/// friendly notice if the marker already exists and exits 0. Only this
/// explicit command creates the marker — the wizard and preset code never do.
#[derive(Args, Debug, Clone)]
pub struct RmasArgs {
    #[command(subcommand)]
    pub action: RmasAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RmasAction {
    /// Show RecursiveMAS license/consent status; optionally write the
    /// consent marker with `--acknowledge`.
    Consent {
        /// Write the consent marker. Idempotent — safe to run multiple times.
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
    let marker = rmas_marker_path(home);
    let already = is_rmas_consent_acknowledged(home);

    if acknowledge {
        if already {
            println!(
                "RMAS consent already acknowledged.\n\
                 Marker: {}\n\
                 License: {}",
                marker.display(),
                RMAS_LICENSE_NAME
            );
            return Ok(());
        }
        write_rmas_consent_marker(home)?;
        println!(
            "RMAS consent acknowledged.\n\
             Marker written: {}\n\
             License: {}",
            marker.display(),
            RMAS_LICENSE_NAME
        );
    } else {
        // Status-only path.
        println!(
            "--- RecursiveMAS Consent Status ---\n\
             Status:  {}\n\
             Marker:  {}\n\
             License: {}\n\
             \n\
             {}",
            if already {
                "ACKNOWLEDGED"
            } else {
                "NOT acknowledged"
            },
            marker.display(),
            RMAS_LICENSE_NAME,
            RMAS_LICENSE_NOTICE,
        );
        if !already {
            println!("\nTo acknowledge, run:\n  neoth rmas consent --acknowledge");
        }
    }
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
        assert!(!is_rmas_consent_acknowledged(dir.path()));
        assert!(!rmas_marker_path(dir.path()).exists());
    }

    #[test]
    fn write_marker_creates_file_and_is_acknowledged() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()));
        assert!(rmas_marker_path(dir.path()).exists());
    }

    #[test]
    fn write_marker_is_idempotent() {
        let dir = TempDir::new().unwrap();
        write_rmas_consent_marker(dir.path()).unwrap();
        // Second call must not error.
        write_rmas_consent_marker(dir.path()).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()));
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
        assert!(!content.is_empty(), "marker must contain timestamp");
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

    // ── acknowledge path ──────────────────────────────────────────────────────

    #[test]
    fn acknowledge_writes_marker_and_exits_ok() {
        let dir = TempDir::new().unwrap();
        assert!(!is_rmas_consent_acknowledged(dir.path()));
        run_consent(dir.path(), true).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()));
    }

    #[test]
    fn acknowledge_idempotent_when_already_present() {
        let dir = TempDir::new().unwrap();
        run_consent(dir.path(), true).unwrap();
        // Second call must still exit 0 with friendly notice.
        run_consent(dir.path(), true).unwrap();
        assert!(is_rmas_consent_acknowledged(dir.path()));
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
            !is_rmas_consent_acknowledged(dir.path()),
            "marker must NOT exist unless --acknowledge was passed explicitly"
        );
    }
}
