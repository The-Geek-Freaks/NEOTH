//! GOLD-ADAPT-HANDY-07 — GPU/accelerator detection + FMA3 guard for the
//! media pipeline (STT backend selection).
//!
//! Adapted from Handy `src-tauri/src/managers/transcription.rs:785–828`.
//!
//! This is the **media-layer** hardware view. The system-level
//! `daemon::hardware` / `daemon::accelerator` modules cover the wizard UI;
//! this module is concerned only with selecting the right STT compute
//! backend at transcription init time:
//!
//! - CPU capability flags (FMA3, AVX2, AVX) detected via
//!   `is_x86_feature_detected!` — available in stable Rust on x86/x86_64.
//! - Best-available accelerator class derived from the existing
//!   `daemon::accelerator::detect()` (no extra deps).
//! - An injectable guard (`require_fma3`) that refuses an FMA3-requiring
//!   backend when FMA3 is absent — avoids SIGILL crashes on pre-Haswell
//!   CPUs (Handy's exact guard, ported to Rust).
//!
//! # Design constraints
//! - **No new Cargo deps.** Pure `std` + intra-crate `daemon::accelerator`.
//! - **Testable on any hardware.** The guard takes an injected `bool` so
//!   tests do not need actual old CPUs to cover the failure path.
//! - **Non-blocking.** Everything is synchronous; the accelerator probe
//!   calls `nvidia-smi` only on the first use (see `daemon::accelerator`
//!   for the 500ms timeout).

use std::fmt;

use crate::daemon::accelerator::{self, Accelerator};

// ── CPU capability flags ─────────────────────────────────────────────────────

/// Detected x86/x86_64 SIMD capabilities.
///
/// On non-x86 targets every flag is `false`; callers should treat `false`
/// as "unknown / not applicable" rather than "definitely absent".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuCaps {
    /// FMA3 — Fused Multiply-Add (requires Haswell / AMD Piledriver, 2013+).
    /// Candle's metal + some whisper.cpp AVX paths require this.
    pub fma3: bool,
    /// AVX2 — 256-bit integer/float ops (Haswell+, 2013).
    pub avx2: bool,
    /// AVX — 256-bit float ops (Sandy Bridge+, 2011).
    pub avx: bool,
}

impl CpuCaps {
    /// Probe the running CPU.
    ///
    /// On x86_64: uses `std::is_x86_feature_detected!` which reads the CPUID
    /// leaf at runtime — zero syscalls, no shell-out.
    /// On non-x86 targets: returns all-false (struct default).
    #[must_use]
    pub fn detect() -> Self {
        Self {
            fma3: detect_fma3(),
            avx2: detect_avx2(),
            avx: detect_avx(),
        }
    }
}

impl fmt::Display for CpuCaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fma3={} avx2={} avx={}",
            self.fma3, self.avx2, self.avx
        )
    }
}

// ── Accelerator class ────────────────────────────────────────────────────────

/// Best-available compute class for the STT backend. Mirrors
/// `daemon::accelerator::Accelerator` but lives in the media module so
/// higher layers do not need to import the daemon namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceleratorClass {
    /// NVIDIA CUDA (fastest; requires NVIDIA driver).
    Cuda,
    /// Apple Metal (GPU-accelerated; macOS only).
    Metal,
    /// Intel OpenVINO (Intel iGPU / Arc / NPU).
    OpenVino,
    /// Plain CPU (always works; slow on 3–7 B models).
    Cpu,
}

impl AcceleratorClass {
    /// Stable lowercase identifier for logs + configuration matching.
    pub fn as_str(self) -> &'static str {
        match self {
            AcceleratorClass::Cuda => "cuda",
            AcceleratorClass::Metal => "metal",
            AcceleratorClass::OpenVino => "openvino",
            AcceleratorClass::Cpu => "cpu",
        }
    }
}

impl fmt::Display for AcceleratorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Accelerator> for AcceleratorClass {
    fn from(a: Accelerator) -> Self {
        match a {
            Accelerator::Cuda => AcceleratorClass::Cuda,
            Accelerator::Metal => AcceleratorClass::Metal,
            Accelerator::OpenVino => AcceleratorClass::OpenVino,
            Accelerator::Cpu => AcceleratorClass::Cpu,
        }
    }
}

// ── HwProbe ──────────────────────────────────────────────────────────────────

/// Combined hardware view for STT/media backend selection.
///
/// Constructed once at STT init; passed to the backend factory and cached
/// for the lifetime of the `WhisperEngine` (or equivalent backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwProbe {
    /// CPU capability flags for the running core.
    pub cpu_caps: CpuCaps,
    /// Best available compute accelerator.
    pub accelerator: AcceleratorClass,
}

impl HwProbe {
    /// Probe the current host. Pure read; never panics; blocks for at most
    /// ~500 ms on the first call (due to the `nvidia-smi` timeout inside
    /// `daemon::accelerator`).
    #[must_use]
    pub fn detect() -> Self {
        Self {
            cpu_caps: CpuCaps::detect(),
            accelerator: AcceleratorClass::from(accelerator::detect()),
        }
    }

    /// `true` when the host has a non-CPU accelerator (CUDA / Metal /
    /// OpenVINO) — convenience for backend logging.
    pub fn has_gpu(&self) -> bool {
        self.accelerator != AcceleratorClass::Cpu
    }
}

impl fmt::Display for HwProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "accelerator={} cpu_caps=[{}]",
            self.accelerator, self.cpu_caps
        )
    }
}

// ── FMA3 guard ───────────────────────────────────────────────────────────────

/// Refuse a backend that requires FMA3 when the CPU does not support it.
///
/// Takes the FMA3 flag **by value** so callers can inject `false` in tests
/// without needing real old hardware.  The candle + whisper.cpp SIMD paths
/// that emit `fma` instructions will `SIGILL` on pre-Haswell CPUs if this
/// guard is not checked before backend construction.
///
/// # Errors
/// Returns `Err` with a human-readable message when `fma3_present` is
/// `false`.  The caller should log the message and either fall back to a
/// non-FMA3 backend or surface it to the operator.
pub fn require_fma3(fma3_present: bool) -> Result<(), String> {
    if fma3_present {
        Ok(())
    } else {
        Err(
            "the selected STT backend requires FMA3 (Fused Multiply-Add) \
             SIMD instructions but this CPU does not support them. \
             Upgrade to a Haswell (Intel 2013+) or Piledriver (AMD 2012+) \
             CPU, or select a CPU-only backend that does not use FMA3."
                .to_string(),
        )
    }
}

// ── Internal feature detection helpers ───────────────────────────────────────
//
// Each helper is its own fn so the cfg attributes stay local and do not
// infect the public API.

#[inline]
fn detect_fma3() -> bool {
    // `is_x86_feature_detected!` is a stable std macro on x86 / x86_64.
    // On other architectures the cfg guard makes the whole body `false`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("fma")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[inline]
fn detect_avx2() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[inline]
fn detect_avx() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("avx")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HwProbe::detect ──────────────────────────────────────────────────────

    #[test]
    fn probe_returns_populated_struct() {
        let probe = HwProbe::detect();
        // accelerator is always one of the four known classes.
        let valid = ["cuda", "metal", "openvino", "cpu"];
        assert!(
            valid.contains(&probe.accelerator.as_str()),
            "unknown accelerator class: {}",
            probe.accelerator
        );
    }

    #[test]
    fn probe_display_contains_accelerator_and_cpu_caps() {
        let probe = HwProbe::detect();
        let s = probe.to_string();
        assert!(s.contains("accelerator="), "missing accelerator= in '{s}'");
        assert!(s.contains("fma3="), "missing fma3= in '{s}'");
        assert!(s.contains("avx2="), "missing avx2= in '{s}'");
        assert!(s.contains("avx="), "missing avx= in '{s}'");
    }

    #[test]
    fn probe_has_gpu_is_false_on_cpu_class() {
        let probe = HwProbe {
            cpu_caps: CpuCaps::default(),
            accelerator: AcceleratorClass::Cpu,
        };
        assert!(!probe.has_gpu());
    }

    #[test]
    fn probe_has_gpu_is_true_on_cuda_class() {
        let probe = HwProbe {
            cpu_caps: CpuCaps::default(),
            accelerator: AcceleratorClass::Cuda,
        };
        assert!(probe.has_gpu());
    }

    // ── CpuCaps ──────────────────────────────────────────────────────────────

    #[test]
    fn cpu_caps_detect_returns_bool_fields() {
        let caps = CpuCaps::detect();
        // Just type-check that the bools are accessible; the actual value is
        // host-dependent and we do not gate on specific hardware.
        let _: bool = caps.fma3;
        let _: bool = caps.avx2;
        let _: bool = caps.avx;
    }

    #[test]
    fn cpu_caps_display_contains_all_flags() {
        let caps = CpuCaps {
            fma3: true,
            avx2: false,
            avx: true,
        };
        let s = caps.to_string();
        assert!(s.contains("fma3=true"), "got: {s}");
        assert!(s.contains("avx2=false"), "got: {s}");
        assert!(s.contains("avx=true"), "got: {s}");
    }

    #[test]
    fn cpu_caps_default_is_all_false() {
        let caps = CpuCaps::default();
        assert!(!caps.fma3);
        assert!(!caps.avx2);
        assert!(!caps.avx);
    }

    // ── AcceleratorClass ─────────────────────────────────────────────────────

    #[test]
    fn accelerator_class_as_str_round_trips() {
        let expected = [
            (AcceleratorClass::Cuda, "cuda"),
            (AcceleratorClass::Metal, "metal"),
            (AcceleratorClass::OpenVino, "openvino"),
            (AcceleratorClass::Cpu, "cpu"),
        ];
        for (cls, s) in expected {
            assert_eq!(cls.as_str(), s);
            assert_eq!(cls.to_string(), s);
        }
    }

    #[test]
    fn accelerator_class_from_daemon_accelerator() {
        assert_eq!(
            AcceleratorClass::from(Accelerator::Cuda),
            AcceleratorClass::Cuda
        );
        assert_eq!(
            AcceleratorClass::from(Accelerator::Metal),
            AcceleratorClass::Metal
        );
        assert_eq!(
            AcceleratorClass::from(Accelerator::OpenVino),
            AcceleratorClass::OpenVino
        );
        assert_eq!(
            AcceleratorClass::from(Accelerator::Cpu),
            AcceleratorClass::Cpu
        );
    }

    // ── require_fma3 (injectable guard) ─────────────────────────────────────
    //
    // These tests inject the bool directly so they pass on any hardware,
    // including pre-Haswell CPUs that lack FMA3.

    #[test]
    fn require_fma3_succeeds_when_flag_is_true() {
        assert!(require_fma3(true).is_ok());
    }

    #[test]
    fn require_fma3_fails_when_flag_is_false() {
        let err = require_fma3(false).unwrap_err();
        assert!(
            err.contains("FMA3"),
            "error message must mention FMA3: {err}"
        );
        assert!(
            err.contains("CPU"),
            "error message must mention CPU: {err}"
        );
    }

    #[test]
    fn require_fma3_error_message_mentions_backend() {
        // The guard's error is surfaced to the operator; it must be
        // actionable (backend + CPU requirement + suggestion).
        let err = require_fma3(false).unwrap_err();
        assert!(err.contains("backend"), "got: {err}");
        assert!(err.contains("Haswell") || err.contains("Piledriver"), "got: {err}");
    }

    #[test]
    fn require_fma3_injected_false_simulates_old_hardware() {
        // Proof: even on a modern CPU that has FMA3 we can simulate the
        // failure path by injecting false — the guard is purely about the
        // injected flag, not the real CPUID result.
        let forced_absent = false; // simulate pre-Haswell
        assert!(require_fma3(forced_absent).is_err());
    }
}
