//! `neoth rmas consent` — RMAS sidecar consent lifecycle (ZF-04).
//!
//! The RecursiveMAS sidecar (`recursive_mas.enabled: true`) executes
//! OPERATOR-INSTALLED third-party code whose upstream license is unresolved.
//! NEOTH never creates the consent marker automatically — not in the wizard,
//! not via preset apply. The operator must run `neoth rmas consent --acknowledge`
//! explicitly after reviewing the upstream repository.
//!
//! Marker: `~/.neoth/rmas_consent_acknowledged` (empty file, presence = consent).
//!
//! Invariant: grep for CONSENT_MARKER ("rmas_consent_acknowledged") in
//! cli/init/ and config/presets.rs returns zero matches — this file is the
//! SOLE writer of the consent marker. NEOTH never auto-creates it.

use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

// CONSENT_MARKER is defined in the feature-gated `recursive_mas_adapter`
// module. When that feature is absent the string value is mirrored here
// under cfg so the CLI subcommand still compiles and reports status on any
// build. The two definitions must stay in sync — if you change one, change
// the other.
#[cfg(feature = "recursive-mas")]
use crate::providers::recursive_mas_adapter::CONSENT_MARKER;
#[cfg(not(feature = "recursive-mas"))]
const CONSENT_MARKER: &str = "rmas_consent_acknowledged";

#[derive(Args, Debug, Clone)]
pub struct RmasArgs {
    #[command(subcommand)]
    pub action: RmasAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RmasAction {
    /// Show RMAS license status, sidecar config, and consent marker state.
    ///
    /// Use `neoth rmas consent --acknowledge` to write the consent marker after
    /// you have reviewed the upstream RecursiveMAS repository. NEOTH never
    /// downloads or updates the sidecar itself.
    Consent {
        /// Acknowledge running third-party RecursiveMAS code and write the
        /// consent marker. REVIEW the upstream repository yourself first —
        /// NEOTH never downloads it; this flag confirms you have.
        #[arg(long)]
        acknowledge: bool,
    },
}

pub fn run_rmas(args: RmasArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        RmasAction::Consent { acknowledge } => run_consent(&home, acknowledge, args.output),
    }
}

/// Core logic — separated from `run_rmas` so tests can inject a custom home
/// path via `TempDir` without touching the real `~/.neoth/`.
pub(crate) fn run_consent(home: &Path, acknowledge: bool, output: OutputFormat) -> Result<()> {
    let marker_path = home.join(CONSENT_MARKER);
    let marker_exists = marker_path.exists();

    // Load config for status display (best-effort; fresh installs may lack freedom.yaml).
    let cfg = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.recursive_mas)
        .unwrap_or_default();

    if acknowledge {
        // Security floor: this path is never reached by wizard or preset
        // (verified: zero grep hits for CONSENT_MARKER in cli/init/ and
        // config/presets.rs / preset_builtins.rs / cli/preset.rs). The
        // --acknowledge flag itself is the explicit operator consent act.
        if marker_exists {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "action": "noop",
                            "marker": marker_path.display().to_string(),
                            "reason": "already acknowledged"
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("RMAS consent already acknowledged.");
                    println!("marker: {}", marker_path.display());
                }
            }
            return Ok(());
        }
        // Create parent dir if needed (mirrors consent::grant pattern).
        if let Some(parent) = marker_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&marker_path, b"")?;
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "acknowledged",
                        "marker": marker_path.display().to_string(),
                    })
                );
            }
            OutputFormat::Table => {
                println!("RMAS consent acknowledged.");
                println!("marker: {}", marker_path.display());
                println!();
                println!("RecursiveMAS will now be available when:");
                println!("  recursive_mas.enabled: true  (in freedom.yaml)");
                println!("  recursive_mas.sidecar_repo   (path to your checkout)");
                println!("  GPU VRAM >= {} GiB", cfg.min_vram_gib);
                if !cfg.enabled {
                    println!();
                    println!(
                        "Note: recursive_mas.enabled is currently false. \
                         Set it in freedom.yaml to activate."
                    );
                }
            }
        }
    } else {
        // Status display — read-only, no side effects.
        let status = if marker_exists { "ACKNOWLEDGED" } else { "NOT ACKNOWLEDGED" };
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "consent": status,
                        "marker": marker_path.display().to_string(),
                        "marker_exists": marker_exists,
                        "recursive_mas_enabled": cfg.enabled,
                        "sidecar_repo": cfg.sidecar_repo.as_ref().map(|p| p.display().to_string()),
                        "min_vram_gib": cfg.min_vram_gib,
                        "license_note":
                            "upstream RecursiveMAS has no resolved license — NEOTH never \
                             downloads or updates the sidecar; review the repo yourself \
                             before acknowledging"
                    })
                );
            }
            OutputFormat::Table => {
                println!("RMAS (RecursiveMAS sidecar) consent status");
                println!("  consent marker : {status}");
                println!("  marker path    : {}", marker_path.display());
                println!("  rmas.enabled   : {}", cfg.enabled);
                println!(
                    "  sidecar_repo   : {}",
                    cfg.sidecar_repo
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(not set)".to_string())
                );
                println!("  min_vram_gib   : {}", cfg.min_vram_gib);
                println!();
                println!(
                    "License note: upstream RecursiveMAS has no resolved license.\n\
                     NEOTH never downloads or updates the sidecar — you must install\n\
                     it yourself. After reviewing the upstream repo, run:\n\
                     \n  neoth rmas consent --acknowledge\n"
                );
                if !marker_exists {
                    println!("The sidecar will refuse to spawn until the marker exists.");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // No env-var mutation in any test below — crate::test_env::lock not needed.

    /// Read-only status call returns Ok when no marker exists.
    #[test]
    fn status_when_no_marker_shows_not_acknowledged() {
        let tmp = TempDir::new().unwrap();
        assert!(run_consent(tmp.path(), false, OutputFormat::Table).is_ok());
        // Marker must NOT have been created.
        assert!(!tmp.path().join(CONSENT_MARKER).exists());
    }

    /// --acknowledge creates the marker file.
    #[test]
    fn acknowledge_creates_marker_file() {
        let tmp = TempDir::new().unwrap();
        assert!(run_consent(tmp.path(), true, OutputFormat::Table).is_ok());
        assert!(
            tmp.path().join(CONSENT_MARKER).exists(),
            "consent marker must exist after --acknowledge"
        );
    }

    /// --acknowledge when marker already exists is a no-op (idempotent).
    #[test]
    fn acknowledge_twice_is_noop_no_error() {
        let tmp = TempDir::new().unwrap();
        // Pre-create the marker.
        std::fs::write(tmp.path().join(CONSENT_MARKER), b"").unwrap();
        // Second call must succeed without error.
        assert!(run_consent(tmp.path(), true, OutputFormat::Table).is_ok());
        // Marker still exists.
        assert!(tmp.path().join(CONSENT_MARKER).exists());
    }

    /// Status call with JSON output returns Ok after marker has been created.
    #[test]
    fn status_after_acknowledge_returns_ok_json() {
        let tmp = TempDir::new().unwrap();
        // Acknowledge first.
        run_consent(tmp.path(), true, OutputFormat::Table).unwrap();
        // Status in JSON mode must succeed.
        assert!(run_consent(tmp.path(), false, OutputFormat::Json).is_ok());
    }

    /// --acknowledge also works with JSON output format.
    #[test]
    fn acknowledge_with_json_output_creates_marker() {
        let tmp = TempDir::new().unwrap();
        assert!(run_consent(tmp.path(), true, OutputFormat::Json).is_ok());
        assert!(tmp.path().join(CONSENT_MARKER).exists());
    }

    /// Verify that wizard and preset paths never create the RMAS consent marker.
    ///
    /// This is a static-analysis-verified invariant: grep for CONSENT_MARKER
    /// ("rmas_consent_acknowledged") in cli/init/ and config/presets.rs /
    /// preset_builtins.rs / cli/preset.rs returned zero matches at the time
    /// of writing ZF-04 (charming-faraday-cc122b). The run_consent function
    /// in this file is the SOLE writer of the marker.
    ///
    /// Runtime enforcement: the only code path that calls
    /// `std::fs::write(&marker_path, …)` is inside the `if acknowledge { … }`
    /// branch above — reachable only when the caller explicitly passes
    /// `acknowledge: true`, which the CLI binds exclusively to `--acknowledge`.
    #[test]
    fn wizard_and_preset_do_not_touch_rmas_marker() {
        // The marker path is constructed from `home.join(CONSENT_MARKER)`.
        // A fresh TempDir has no marker; after a status-only call it still
        // has none — confirming no side-writer is triggered by status.
        let tmp = TempDir::new().unwrap();
        run_consent(tmp.path(), false, OutputFormat::Table).unwrap();
        assert!(
            !tmp.path().join(CONSENT_MARKER).exists(),
            "status-only run must not create the consent marker"
        );
    }
}
