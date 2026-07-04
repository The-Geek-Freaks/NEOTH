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

use std::path::PathBuf;

use crate::config::RecursiveMasConfig;
use crate::daemon::resource_watch::VramReading;

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
