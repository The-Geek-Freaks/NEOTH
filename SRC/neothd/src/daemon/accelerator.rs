//! Hardware-accelerator detection — D14b prerequisite.
//!
//! Probes the host for the fastest inference backend before the wizard
//! asks the operator whether to use local Qwen at all. The detection is
//! best-effort and side-effect-free: every probe times out fast, never
//! mutates state, never downloads anything.
//!
//! Detection order (first hit wins):
//!   1. CUDA  — env `CUDA_PATH` set, `nvidia-smi` runs successfully
//!   2. Metal — running on macOS (Apple Silicon or x86 — both expose Metal)
//!   3. OpenVINO — env `OPENVINO_ROOT_DIR` set OR `intel-oneapi` path present
//!   4. CPU   — always available, fallback
//!
//! Operator can override via `freedom.yaml::accelerator_override` if the
//! detection picks wrong (rare but happens on dual-GPU + WSL setups).
//!
//! Detection is pure-Rust + std::process — no candle feature deps yet, so
//! the wizard can run on a fresh install before the operator decides
//! whether to enable the GPU build.

use std::time::Duration;

/// Available inference backends. Variants are ordered roughly by typical
/// performance; the auto-detect picks the first hit in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accelerator {
    /// NVIDIA CUDA. Probed via `CUDA_PATH` env + nvidia-smi.
    Cuda,
    /// Apple Metal. Default on macOS hosts (no probe needed).
    Metal,
    /// Intel OpenVINO. Probed via `OPENVINO_ROOT_DIR` env.
    OpenVino,
    /// Fallback — always works, always slow on 3-7B models.
    Cpu,
}

impl Accelerator {
    /// Stable identifier for serde + CLI + log fields.
    pub fn as_str(self) -> &'static str {
        match self {
            Accelerator::Cuda => "cuda",
            Accelerator::Metal => "metal",
            Accelerator::OpenVino => "openvino",
            Accelerator::Cpu => "cpu",
        }
    }

    /// One-line operator-facing description shown in the wizard.
    pub fn description(self) -> &'static str {
        match self {
            Accelerator::Cuda => "NVIDIA CUDA — fastest, requires NVIDIA driver",
            Accelerator::Metal => "Apple Metal — GPU-accelerated on macOS",
            Accelerator::OpenVino => "Intel OpenVINO — Intel iGPU / Arc / NPU",
            Accelerator::Cpu => "CPU — works everywhere, slow on 3-7B models",
        }
    }

    /// Parse from the operator-visible identifier. Used by the
    /// `--accelerator-override` CLI flag.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cuda" | "gpu" | "nvidia" => Some(Accelerator::Cuda),
            "metal" | "apple" => Some(Accelerator::Metal),
            "openvino" | "intel" => Some(Accelerator::OpenVino),
            "cpu" => Some(Accelerator::Cpu),
            _ => None,
        }
    }
}

/// Pick the best accelerator the current host exposes. Always returns
/// something — at worst, `Cpu`. Never panics, never blocks longer than
/// `PROBE_TIMEOUT` per probe.
pub fn detect() -> Accelerator {
    if cuda_available() {
        return Accelerator::Cuda;
    }
    if metal_available() {
        return Accelerator::Metal;
    }
    if openvino_available() {
        return Accelerator::OpenVino;
    }
    Accelerator::Cpu
}

/// Detection result with the alternatives that were also probed. Used to
/// show the operator "here's what we found, plus the fallbacks if you
/// want to force one".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub picked: Accelerator,
    pub cuda: bool,
    pub metal: bool,
    pub openvino: bool,
}

pub fn probe() -> Probe {
    let cuda = cuda_available();
    let metal = metal_available();
    let openvino = openvino_available();
    let picked = if cuda {
        Accelerator::Cuda
    } else if metal {
        Accelerator::Metal
    } else if openvino {
        Accelerator::OpenVino
    } else {
        Accelerator::Cpu
    };
    Probe {
        picked,
        cuda,
        metal,
        openvino,
    }
}

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

fn cuda_available() -> bool {
    // Cheap env-var path first — set by every NVIDIA toolkit installer.
    if std::env::var("CUDA_PATH").is_ok() {
        return true;
    }
    // Slow path: actually exec `nvidia-smi`. Bounded by PROBE_TIMEOUT so a
    // hung driver does not block startup. Windows + Linux both ship the
    // binary on `PATH` when the driver is installed.
    cmd_succeeds("nvidia-smi", &["-L"], PROBE_TIMEOUT)
}

fn metal_available() -> bool {
    // Metal is the default GPU API on macOS Apple Silicon AND modern x86.
    // We treat presence of macOS as "Metal works" — there's no useful
    // probe short of compiling a kernel.
    cfg!(target_os = "macos")
}

fn openvino_available() -> bool {
    // OpenVINO toolkit installer sets one of these envs. The Intel oneAPI
    // installer sets `ONEAPI_ROOT`. Both indicate a usable install without
    // shelling out.
    std::env::var("OPENVINO_ROOT_DIR").is_ok()
        || std::env::var("INTEL_OPENVINO_DIR").is_ok()
        || std::env::var("ONEAPI_ROOT").is_ok()
}

fn cmd_succeeds(program: &str, args: &[&str], timeout: Duration) -> bool {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    // Poll wait-with-timeout via try_wait. Cheap loop — never sleeps
    // longer than 25ms so the overall PROBE_TIMEOUT is respected.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {}
            Err(_) => return false,
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_round_trips_through_from_str() {
        for a in [
            Accelerator::Cuda,
            Accelerator::Metal,
            Accelerator::OpenVino,
            Accelerator::Cpu,
        ] {
            let s = a.as_str();
            assert_eq!(Accelerator::from_str(s), Some(a), "round trip {s}");
        }
    }

    #[test]
    fn from_str_accepts_aliases() {
        assert_eq!(Accelerator::from_str("gpu"), Some(Accelerator::Cuda));
        assert_eq!(Accelerator::from_str("nvidia"), Some(Accelerator::Cuda));
        assert_eq!(Accelerator::from_str("apple"), Some(Accelerator::Metal));
        assert_eq!(Accelerator::from_str("intel"), Some(Accelerator::OpenVino));
        assert_eq!(Accelerator::from_str("CUDA"), Some(Accelerator::Cuda));
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(Accelerator::from_str("rocm").is_none());
        assert!(Accelerator::from_str("").is_none());
        assert!(Accelerator::from_str("nope").is_none());
    }

    #[test]
    fn detect_always_returns_something_falls_back_to_cpu() {
        // Detection is host-dependent; we cannot pin to a specific result.
        // What we *can* assert is that something usable comes back.
        let a = detect();
        // All four variants are valid here — just verify it parses.
        assert!(Accelerator::from_str(a.as_str()).is_some());
    }

    #[test]
    fn probe_reports_all_three_flags() {
        let p = probe();
        // Picked must be consistent with the flags.
        match p.picked {
            Accelerator::Cuda => assert!(p.cuda),
            Accelerator::Metal => assert!(p.metal),
            Accelerator::OpenVino => assert!(p.openvino),
            Accelerator::Cpu => {
                assert!(!p.cuda);
                assert!(!p.openvino);
                // Metal can only be true on macOS hosts; CPU + Metal=true
                // together would be a logic bug in pick().
                if cfg!(target_os = "macos") {
                    // On macOS, Metal would have been picked first. If
                    // we got here, Metal must be false too.
                    assert!(!p.metal);
                }
            }
        }
    }

    #[test]
    fn description_is_human_readable_one_liner() {
        for a in [
            Accelerator::Cuda,
            Accelerator::Metal,
            Accelerator::OpenVino,
            Accelerator::Cpu,
        ] {
            let d = a.description();
            assert!(!d.is_empty());
            assert!(!d.contains('\n'), "description for {a:?} must be one line");
        }
    }
}
