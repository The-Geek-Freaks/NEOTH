//! GOLD-ADAPT-RMAS-02 — resource gate for the optional RecursiveMAS
//! sidecar (latent-recursion council refinement).
//!
//! The gate is pure logic and compiles in EVERY build (so the default
//! test suite covers it); only the live sidecar adapter (RMAS-03) sits
//! behind the `recursive-mas` Cargo feature. Order of checks:
//!   1. `freedom.yaml::recursive_mas.enabled` (master switch, default off)
//!   2. total GPU VRAM ≥ `min_vram_gib` (latent-weights method — a
//!      CPU-only host can never run it; `None` counts as 0 GiB)
//!   3. operator-installed checkout present (`sidecar_repo` contains
//!      `inference_mas.py` — NEOTH never downloads the code or weights
//!      itself; upstream license is unresolved, invoke-only).
//!
//! Callers pass `hardware::probe(..).vram.as_ref()` (the live reading) —
//! the gate deliberately takes only the VRAM slice, not the whole
//! `HardwareReport`, so it unit-tests without a hardware probe.

use std::path::{Path, PathBuf};

use crate::config::RecursiveMasConfig;
use crate::daemon::resource_watch::VramReading;
use anyhow::{Context, Result};

/// Consent marker file name under `~/.neoth/`. Defined here (not in the
/// feature-gated `recursive_mas_adapter`) so the always-compiled
/// `neoth rmas consent` CLI and the gated adapter share ONE source of truth —
/// otherwise the write path and the spawn-time check drift apart and the
/// consent gate becomes unsatisfiable.
pub const CONSENT_MARKER: &str = "rmas_consent_acknowledged";
/// Canonical `YYYY-MM-DDTHH:MM:SSZ` acknowledgement payload length.
pub const CONSENT_MARKER_BYTES: usize = 20;

pub fn consent_marker_path(home: &Path) -> PathBuf {
    home.join(CONSENT_MARKER)
}

/// Validate the instance-bound third-party-code acknowledgement without
/// following a symlink/reparse point or trusting path metadata captured before
/// the read. The shared bounded reader also requires one regular, single-link
/// file and verifies the opened handle against the exact namespace entry.
pub fn code_acknowledgement_present(home: &Path) -> Result<bool> {
    let marker = consent_marker_path(home);
    let bytes = match crate::updater::self_update::read_control_file_bounded_nofollow(
        home,
        &marker,
        CONSENT_MARKER_BYTES,
        "RecursiveMAS code acknowledgement",
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            return Ok(false);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "validate RecursiveMAS code acknowledgement {}",
                    marker.display()
                )
            });
        }
    };

    anyhow::ensure!(
        bytes.len() == CONSENT_MARKER_BYTES,
        "RecursiveMAS code acknowledgement has invalid canonical length"
    );
    let text = std::str::from_utf8(&bytes)
        .context("RecursiveMAS code acknowledgement is not valid UTF-8")?;
    let parsed = chrono::DateTime::parse_from_rfc3339(text)
        .context("RecursiveMAS code acknowledgement timestamp is malformed")?;
    anyhow::ensure!(
        parsed.offset().local_minus_utc() == 0
            && parsed
                .with_timezone(&chrono::Utc)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
                == text,
        "RecursiveMAS code acknowledgement is not canonical UTC"
    );
    Ok(true)
}

/// Typed refusal reason — callers surface this verbatim to the operator
/// (actionable: which knob to turn), never a bare bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RmasUnavailableReason {
    /// `recursive_mas.enabled` is `false` (the default).
    Disabled,
    /// Not enough total GPU VRAM for latent recursion.
    InsufficientVram { have_gib: u32, need_gib: u32 },
    /// No operator-installed RecursiveMAS checkout at `sidecar_repo`.
    SidecarNotInstalled { expected: PathBuf },
}

impl std::fmt::Display for RmasUnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(
                f,
                "recursive_mas is disabled — set `recursive_mas.enabled: true` in freedom.yaml to opt in"
            ),
            Self::InsufficientVram { have_gib, need_gib } => write!(
                f,
                "insufficient GPU VRAM for RecursiveMAS: have {have_gib} GiB, need {need_gib} GiB (latent recursion is GPU-only)"
            ),
            Self::SidecarNotInstalled { expected } => write!(
                f,
                "RecursiveMAS sidecar not installed — expected {} (set `recursive_mas.sidecar_repo` to your checkout; NEOTH never downloads it)",
                expected.display()
            ),
        }
    }
}

/// The RMAS-02 gate: `Ok(())` iff the operator enabled the feature, the
/// host has enough VRAM, and the sidecar checkout is present.
pub fn recursive_mas_available(
    config: &RecursiveMasConfig,
    vram: Option<&VramReading>,
) -> Result<(), RmasUnavailableReason> {
    if !config.enabled {
        return Err(RmasUnavailableReason::Disabled);
    }
    let have_gib = vram.map(|v| v.total_mib / 1024).unwrap_or(0);
    if have_gib < config.min_vram_gib {
        return Err(RmasUnavailableReason::InsufficientVram {
            have_gib,
            need_gib: config.min_vram_gib,
        });
    }
    let Some(repo) = config.sidecar_repo.as_ref() else {
        return Err(RmasUnavailableReason::SidecarNotInstalled {
            expected: PathBuf::from("<recursive_mas.sidecar_repo unset>"),
        });
    };
    let marker = repo.join("inference_mas.py");
    if !marker.exists() {
        return Err(RmasUnavailableReason::SidecarNotInstalled { expected: marker });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_cfg() -> RecursiveMasConfig {
        RecursiveMasConfig {
            enabled: true,
            ..RecursiveMasConfig::default()
        }
    }

    #[test]
    fn disabled_by_default_refuses() {
        let cfg = RecursiveMasConfig::default();
        assert_eq!(
            recursive_mas_available(&cfg, None),
            Err(RmasUnavailableReason::Disabled)
        );
    }

    #[test]
    fn cpu_only_host_refuses_with_insufficient_vram() {
        assert_eq!(
            recursive_mas_available(&enabled_cfg(), None),
            Err(RmasUnavailableReason::InsufficientVram {
                have_gib: 0,
                need_gib: 12
            })
        );
    }

    #[test]
    fn small_gpu_refuses_with_actual_gib_reported() {
        let v = VramReading {
            used_mib: 1000,
            total_mib: 8192, // 8 GiB < 12 GiB default
        };
        assert_eq!(
            recursive_mas_available(&enabled_cfg(), Some(&v)),
            Err(RmasUnavailableReason::InsufficientVram {
                have_gib: 8,
                need_gib: 12
            })
        );
    }

    #[test]
    fn big_gpu_without_sidecar_refuses_sidecar_not_installed() {
        let v = VramReading {
            used_mib: 4000,
            total_mib: 24_576, // 24 GiB
        };
        assert!(matches!(
            recursive_mas_available(&enabled_cfg(), Some(&v)),
            Err(RmasUnavailableReason::SidecarNotInstalled { .. })
        ));
    }

    #[test]
    fn fully_provisioned_host_passes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("inference_mas.py"), "# marker").unwrap();
        let cfg = RecursiveMasConfig {
            enabled: true,
            sidecar_repo: Some(dir.path().to_path_buf()),
            ..RecursiveMasConfig::default()
        };
        let v = VramReading {
            used_mib: 4000,
            total_mib: 24_576,
        };
        assert_eq!(recursive_mas_available(&cfg, Some(&v)), Ok(()));
    }
}
