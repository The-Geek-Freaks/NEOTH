//! OH-04 — device detection → local-AI tier recommendation.
//!
//! Provides a snapshot of the host's hardware relevant to local LLM
//! suitability, and a pure tier-recommendation function so callers (e.g.
//! OH-02 `onboarding-status`) can surface a human-readable verdict without
//! shelling out to vendor tools.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Lightweight hardware snapshot used to recommend a local-AI deployment tier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub total_ram_gb: f64,
    pub cpu_cores: usize,
    /// Best-effort GPU presence flag.  See `detect_device_profile` for
    /// detection notes.
    pub gpu_present: bool,
}

/// Recommended deployment tier derived from `DeviceProfile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalAiTier {
    /// <8 GB RAM, no GPU: prefer cloud provider; local models will be slow.
    CloudFirst,
    /// 8–15 GB RAM, no GPU: can run small local models as fallback.
    Hybrid,
    /// ≥16 GB RAM or GPU present: local-capable; full local inference viable.
    LocalCapable,
}

impl LocalAiTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CloudFirst => "cloud-first",
            Self::Hybrid => "hybrid",
            Self::LocalCapable => "local-capable",
        }
    }

    pub fn rationale(self) -> &'static str {
        match self {
            Self::CloudFirst => "RAM <8 GB — local inference will be slow; use a cloud provider.",
            Self::Hybrid => "RAM 8–15 GB — small local models viable as fallback.",
            Self::LocalCapable => "RAM ≥16 GB or GPU detected — full local inference supported.",
        }
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Probe the host hardware and return a `DeviceProfile`.
///
/// Uses `sysinfo` for RAM and CPU; GPU detection is best-effort:
///
/// - Checks the `CUDA_VISIBLE_DEVICES` / `HIP_VISIBLE_DEVICES` env vars
///   (set by CUDA / ROCm drivers when a GPU is present/assigned).
/// - Checks `METAL_DEVICE_WRAPPER_TYPE` (macOS Metal tooling).
///
/// // neoth: No vendor CLI (nvidia-smi, rocm-smi, etc.) is shelled out here
/// // because (a) they may not be on PATH, (b) they can take >100 ms, and
/// // (c) this fn is called from a sync context.  A more thorough GPU probe
/// // should be added when the `hardware` crate surface is extended.
pub fn detect_device_profile() -> DeviceProfile {
    use sysinfo::System;

    // RAM
    let mut sys = System::new();
    sys.refresh_memory();
    let total_ram_gb = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);

    // CPU
    sys.refresh_cpu_all();
    let cpu_cores = sys.cpus().len().max(1);

    // GPU — env-var heuristic (best-effort, cross-platform, zero shell-out)
    let gpu_present = std::env::var("CUDA_VISIBLE_DEVICES")
        .ok()
        .filter(|v| !v.is_empty() && v != "NoDevFiles")
        .is_some()
        || std::env::var("HIP_VISIBLE_DEVICES")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
        || std::env::var("METAL_DEVICE_WRAPPER_TYPE")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some();

    DeviceProfile {
        total_ram_gb,
        cpu_cores,
        gpu_present,
    }
}

// ---------------------------------------------------------------------------
// Pure tier logic (unit-testable, no I/O)
// ---------------------------------------------------------------------------

/// Derive a `LocalAiTier` from RAM and GPU presence.
///
/// Thresholds:
/// - `ram_gb < 8`              → `CloudFirst`
/// - `8 ≤ ram_gb < 16`        → `Hybrid`
/// - `ram_gb ≥ 16 || gpu`     → `LocalCapable`
pub fn recommend_tier(ram_gb: f64, gpu_present: bool) -> LocalAiTier {
    if gpu_present || ram_gb >= 16.0 {
        LocalAiTier::LocalCapable
    } else if ram_gb >= 8.0 {
        LocalAiTier::Hybrid
    } else {
        LocalAiTier::CloudFirst
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_below_8gb_no_gpu_is_cloud_first() {
        assert_eq!(recommend_tier(4.0, false), LocalAiTier::CloudFirst);
        assert_eq!(recommend_tier(7.99, false), LocalAiTier::CloudFirst);
    }

    #[test]
    fn tier_8gb_no_gpu_is_hybrid() {
        assert_eq!(recommend_tier(8.0, false), LocalAiTier::Hybrid);
        assert_eq!(recommend_tier(15.99, false), LocalAiTier::Hybrid);
    }

    #[test]
    fn tier_16gb_no_gpu_is_local_capable() {
        assert_eq!(recommend_tier(16.0, false), LocalAiTier::LocalCapable);
        assert_eq!(recommend_tier(64.0, false), LocalAiTier::LocalCapable);
    }

    #[test]
    fn tier_gpu_overrides_low_ram() {
        // GPU present but RAM <8 GB → still LocalCapable
        assert_eq!(recommend_tier(4.0, true), LocalAiTier::LocalCapable);
        assert_eq!(recommend_tier(0.0, true), LocalAiTier::LocalCapable);
    }

    #[test]
    fn tier_gpu_with_hybrid_ram_is_local_capable() {
        assert_eq!(recommend_tier(12.0, true), LocalAiTier::LocalCapable);
    }

    #[test]
    fn as_str_and_rationale_non_empty() {
        for tier in [
            LocalAiTier::CloudFirst,
            LocalAiTier::Hybrid,
            LocalAiTier::LocalCapable,
        ] {
            assert!(!tier.as_str().is_empty());
            assert!(!tier.rationale().is_empty());
        }
    }
}
