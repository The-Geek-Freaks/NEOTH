//! W-01 — GPU probe primitives.
//!
//! Pure-data + classifier surface for the wizard's GPU detection
//! step. The wizard runs platform-specific subprocess probes
//! (`nvidia-smi`, `rocm-smi`, `system_profiler SPDisplaysDataType`)
//! that feed their parsed output into [`classify_from_subprocess`]
//! which returns a [`GpuReport`]. The W-03 RecommendationEngine
//! reads [`GpuReport::vram_mib`] to pick the qwen model tier.
//!
//! ## Why a primitive + classifier split
//!
//! The actual subprocess calls live in OS-specific wrapper code
//! that's hard to unit-test on the CI host. The classifier here
//! takes already-captured stdout text + parses it; tests pin
//! every recognised output shape against real `nvidia-smi`
//! samples.

use serde::{Deserialize, Serialize};

/// One detected GPU class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuKind {
    /// NVIDIA CUDA — preferred for whisper-rs + qwen GGML on
    /// Linux/Windows.
    Cuda,
    /// AMD ROCm — preferred on Linux when no NVIDIA is present.
    Rocm,
    /// Apple Silicon Metal — macOS default; whisper-rs accelerates
    /// via Metal Performance Shaders.
    Metal,
    /// No accelerator detected — CPU fallback. Operator on
    /// integrated GPU or VM without passthrough lands here.
    Cpu,
}

impl GpuKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Rocm => "rocm",
            Self::Metal => "metal",
            Self::Cpu => "cpu",
        }
    }

    /// True when this kind supports the qwen2.5 GPU-accelerated
    /// inference path — W-03's RecommendationEngine consults this
    /// to decide whether to recommend a GPU-tier model at all.
    pub fn can_accelerate(self) -> bool {
        !matches!(self, Self::Cpu)
    }
}

/// One GPU's probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuReport {
    pub kind: GpuKind,
    /// VRAM in MiB. `None` when the probe failed to parse a value
    /// (e.g. `nvidia-smi` query format changed upstream); the
    /// recommendation engine treats unknown VRAM as "assume
    /// minimum tier".
    pub vram_mib: Option<u32>,
    /// Vendor string verbatim from the probe (`NVIDIA`,
    /// `Advanced Micro Devices, Inc.`, `Apple`). Operators see this
    /// in the wizard summary.
    pub vendor: Option<String>,
    /// Marketing name (`NVIDIA GeForce RTX 4090`, `Apple M2 Max`).
    pub name: Option<String>,
}

impl GpuReport {
    /// CPU-fallback constructor — used when no GPU probe found
    /// anything. Operators see this on locked-down VMs and
    /// integrated-graphics-only laptops.
    pub fn cpu() -> Self {
        Self {
            kind: GpuKind::Cpu,
            vram_mib: None,
            vendor: None,
            name: None,
        }
    }

    /// Operator-facing local-model tier for this GPU's VRAM.
    ///
    /// GOLD-ADOPT-10: routes through `models::selector::recommended_tier_label`,
    /// the single source of truth, which sizes models against NEOTH's **F16
    /// candle path**. The old hardcoded thresholds (≥24 GiB → 72B) assumed
    /// quantized inference and recommended models that won't actually load
    /// (a 72B is ~187 GB in F16; a 24 GiB GPU holds a 7B).
    pub fn recommended_model_tier(&self) -> &'static str {
        crate::models::selector::recommended_tier_label(self.vram_mib)
    }
}

/// Parse an `nvidia-smi --query-gpu=name,memory.total --format=csv,
/// noheader,nounits` output line into a [`GpuReport`]. One line in,
/// one report out. Returns `None` for unparsable input.
pub fn parse_nvidia_smi_line(line: &str) -> Option<GpuReport> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return None;
    }
    let name = parts[0].to_string();
    let vram_mib = parts[1].parse::<u32>().ok()?;
    Some(GpuReport {
        kind: GpuKind::Cuda,
        vram_mib: Some(vram_mib),
        vendor: Some("NVIDIA".to_string()),
        name: Some(name),
    })
}

/// Parse `rocm-smi --showmeminfo vram --csv` output. Expects a
/// header line + one data line per GPU. Returns the first GPU's
/// report (multi-GPU support deferred).
pub fn parse_rocm_smi_output(output: &str) -> Option<GpuReport> {
    let mut lines = output.lines().filter(|l| !l.trim().is_empty());
    let _header = lines.next()?;
    let data = lines.next()?;
    let parts: Vec<&str> = data.split(',').map(|s| s.trim()).collect();
    // rocm-smi shape: `device, vram_total_b, vram_used_b`.
    if parts.len() < 2 {
        return None;
    }
    let vram_bytes: u64 = parts[1].parse().ok()?;
    let vram_mib = (vram_bytes / 1024 / 1024) as u32;
    Some(GpuReport {
        kind: GpuKind::Rocm,
        vram_mib: Some(vram_mib),
        vendor: Some("Advanced Micro Devices, Inc.".to_string()),
        name: Some(parts[0].to_string()),
    })
}

/// Parse macOS `system_profiler SPDisplaysDataType -json` output.
/// Expects the standard top-level shape:
/// `{"SPDisplaysDataType": [{"sppci_model": "...", "_name": "..."}]}`.
/// VRAM on Apple Silicon is shared with system RAM → returns
/// `None` for the VRAM field (the wizard prompts the operator to
/// pick a tier manually on Apple Silicon).
pub fn parse_system_profiler_output(output: &str) -> Option<GpuReport> {
    let v: serde_json::Value = serde_json::from_str(output).ok()?;
    let display_list = v.get("SPDisplaysDataType")?.as_array()?;
    let first = display_list.first()?;
    let name = first
        .get("sppci_model")
        .and_then(|x| x.as_str())
        .or_else(|| first.get("_name").and_then(|x| x.as_str()))?;
    Some(GpuReport {
        kind: GpuKind::Metal,
        vram_mib: None, // unified memory — not directly probable here
        vendor: Some("Apple".to_string()),
        name: Some(name.to_string()),
    })
}

/// Top-level classifier: pick the highest-confidence probe output.
/// Operators on multi-vendor systems (rare; some workstations have
/// both NVIDIA + integrated AMD) get the CUDA report because that's
/// what the inference path uses.
pub fn classify_from_subprocess(
    nvidia_smi_stdout: Option<&str>,
    rocm_smi_stdout: Option<&str>,
    system_profiler_stdout: Option<&str>,
) -> GpuReport {
    if let Some(out) = nvidia_smi_stdout {
        if let Some(r) = out.lines().find_map(parse_nvidia_smi_line) {
            return r;
        }
    }
    if let Some(out) = rocm_smi_stdout {
        if let Some(r) = parse_rocm_smi_output(out) {
            return r;
        }
    }
    if let Some(out) = system_profiler_stdout {
        if let Some(r) = parse_system_profiler_output(out) {
            return r;
        }
    }
    GpuReport::cpu()
}

/// Run a probe command with a hard timeout, returning its stdout on success.
/// A hung tool (bad driver) NEVER blocks the caller — onboarding must not stall
/// on a wedged `nvidia-smi`. GR-082: on timeout the child is killed and reaped
/// (the reader thread unblocks when the pipe breaks), so nothing leaks — the
/// reader thread owns only `stdout`, this thread owns the `Child` directly.
fn probe_cmd(cmd: &str, args: &[&str], timeout: std::time::Duration) -> Option<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let ok = stdout.read_to_end(&mut buf).is_ok();
        let _ = tx.send(if ok { Some(buf) } else { None });
    });
    let stdout_buf = rx.recv_timeout(timeout).ok().flatten();
    // Always kill (no-op if the child already exited) + wait, so the child is
    // reaped (no zombie) and the reader thread's `read_to_end` returns.
    let _ = child.kill();
    let status = child.wait().ok();
    match (stdout_buf, status) {
        (Some(buf), Some(s)) if s.success() => Some(String::from_utf8_lossy(&buf).into_owned()),
        _ => None,
    }
}

/// LIVE GPU probe (GOLD-ADOPT-10): run the platform vendor tools + classify
/// into a `GpuReport` with VRAM. Best-effort — a missing/failed/hung tool just
/// means that vendor isn't present; all-absent → CPU. The onboarding wizard
/// calls this to size the local model to the operator's actual VRAM.
pub fn probe_gpu() -> GpuReport {
    const T: std::time::Duration = std::time::Duration::from_millis(1500);
    let nvidia = probe_cmd(
        "nvidia-smi",
        &["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
        T,
    );
    let rocm = probe_cmd("rocm-smi", &["--showmeminfo", "vram", "--csv"], T);
    #[cfg(target_os = "macos")]
    let sysprof = probe_cmd("system_profiler", &["SPDisplaysDataType"], T);
    #[cfg(not(target_os = "macos"))]
    let sysprof: Option<String> = None;
    classify_from_subprocess(nvidia.as_deref(), rocm.as_deref(), sysprof.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn gpu_kind_as_str_pinned() {
        assert_eq!(GpuKind::Cuda.as_str(), "cuda");
        assert_eq!(GpuKind::Rocm.as_str(), "rocm");
        assert_eq!(GpuKind::Metal.as_str(), "metal");
        assert_eq!(GpuKind::Cpu.as_str(), "cpu");
    }

    #[test]
    fn can_accelerate_correct() {
        assert!(GpuKind::Cuda.can_accelerate());
        assert!(GpuKind::Rocm.can_accelerate());
        assert!(GpuKind::Metal.can_accelerate());
        assert!(!GpuKind::Cpu.can_accelerate());
    }

    #[test]
    fn gpu_kind_snake_case_serde() {
        assert_eq!(serde_json::to_string(&GpuKind::Cuda).unwrap(), "\"cuda\"");
        assert_eq!(serde_json::to_string(&GpuKind::Rocm).unwrap(), "\"rocm\"");
        assert_eq!(serde_json::to_string(&GpuKind::Metal).unwrap(), "\"metal\"");
        assert_eq!(serde_json::to_string(&GpuKind::Cpu).unwrap(), "\"cpu\"");
    }

    // ── recommended tier ──────────────────────────────────────────

    // GOLD-ADOPT-10: tiers are now F16-honest (a 72B is ~187 GB in F16 — it
    // never fits a consumer GPU on the candle path). 24 GiB → 7B, not 72B.
    #[test]
    fn recommends_7b_at_24gib() {
        let r = GpuReport {
            kind: GpuKind::Cuda,
            vram_mib: Some(24 * 1024),
            vendor: None,
            name: None,
        };
        assert_eq!(r.recommended_model_tier(), "qwen2.5-7b");
    }

    #[test]
    fn recommends_3b_between_8_and_18gib() {
        // 7B needs ~18 GB F16, so 8..16 GiB lands on the 3B (~7.8 GB).
        for mib in [8 * 1024, 16 * 1024] {
            let r = GpuReport {
                kind: GpuKind::Cuda,
                vram_mib: Some(mib),
                vendor: None,
                name: None,
            };
            assert_eq!(r.recommended_model_tier(), "qwen2.5-3b");
        }
    }

    #[test]
    fn recommends_cloud_below_8gib() {
        // 6 GiB only fits a sub-3B local → the recommendation tier is cloud
        // (the runnable local fit is still a 1.5B, surfaced separately).
        let r = GpuReport {
            kind: GpuKind::Cuda,
            vram_mib: Some(6 * 1024),
            vendor: None,
            name: None,
        };
        assert_eq!(r.recommended_model_tier(), "cloud");
    }

    #[test]
    fn recommends_cloud_for_unknown_vram() {
        let r = GpuReport::cpu();
        assert_eq!(r.recommended_model_tier(), "cloud");
    }

    #[test]
    fn cpu_constructor_zeros_optional_fields() {
        let r = GpuReport::cpu();
        assert_eq!(r.kind, GpuKind::Cpu);
        assert!(r.vram_mib.is_none());
        assert!(r.vendor.is_none());
        assert!(r.name.is_none());
    }

    // ── nvidia-smi parser ─────────────────────────────────────────

    #[test]
    fn parse_nvidia_smi_line_extracts_name_and_vram() {
        let r = parse_nvidia_smi_line("NVIDIA GeForce RTX 4090, 24564").unwrap();
        assert_eq!(r.kind, GpuKind::Cuda);
        assert_eq!(r.vram_mib, Some(24_564));
        assert_eq!(r.name.as_deref(), Some("NVIDIA GeForce RTX 4090"));
        assert_eq!(r.vendor.as_deref(), Some("NVIDIA"));
    }

    #[test]
    fn parse_nvidia_smi_line_handles_whitespace() {
        let r = parse_nvidia_smi_line("  NVIDIA RTX A6000 ,  48000  ").unwrap();
        assert_eq!(r.vram_mib, Some(48_000));
        assert_eq!(r.name.as_deref(), Some("NVIDIA RTX A6000"));
    }

    #[test]
    fn parse_nvidia_smi_line_empty_returns_none() {
        assert!(parse_nvidia_smi_line("").is_none());
        assert!(parse_nvidia_smi_line("   ").is_none());
    }

    #[test]
    fn parse_nvidia_smi_line_missing_vram_returns_none() {
        assert!(parse_nvidia_smi_line("just one field").is_none());
    }

    #[test]
    fn parse_nvidia_smi_line_invalid_vram_returns_none() {
        assert!(parse_nvidia_smi_line("RTX 4090, twenty four thousand").is_none());
    }

    // ── rocm-smi parser ───────────────────────────────────────────

    #[test]
    fn parse_rocm_smi_output_extracts_bytes_to_mib() {
        // 16 GiB in bytes
        let output = "device,vram_total_b,vram_used_b\nrx7900xt,17179869184,4194304";
        let r = parse_rocm_smi_output(output).unwrap();
        assert_eq!(r.kind, GpuKind::Rocm);
        assert_eq!(r.vram_mib, Some(16 * 1024));
        assert_eq!(r.name.as_deref(), Some("rx7900xt"));
    }

    #[test]
    fn parse_rocm_smi_output_missing_data_line_returns_none() {
        assert!(parse_rocm_smi_output("just a header").is_none());
    }

    #[test]
    fn parse_rocm_smi_output_malformed_returns_none() {
        let bad = "device,vram_total_b\nrx,not-a-number";
        assert!(parse_rocm_smi_output(bad).is_none());
    }

    // ── system_profiler parser ────────────────────────────────────

    #[test]
    fn parse_system_profiler_extracts_apple_silicon() {
        let json = r#"{"SPDisplaysDataType":[{"sppci_model":"Apple M2 Max","_name":"M2 Max"}]}"#;
        let r = parse_system_profiler_output(json).unwrap();
        assert_eq!(r.kind, GpuKind::Metal);
        assert_eq!(r.name.as_deref(), Some("Apple M2 Max"));
        assert_eq!(r.vendor.as_deref(), Some("Apple"));
        // Apple unified memory — VRAM probe is None on purpose.
        assert!(r.vram_mib.is_none());
    }

    #[test]
    fn parse_system_profiler_falls_back_to_underscore_name() {
        // Older macOS versions emit `_name` only.
        let json = r#"{"SPDisplaysDataType":[{"_name":"M1"}]}"#;
        let r = parse_system_profiler_output(json).unwrap();
        assert_eq!(r.name.as_deref(), Some("M1"));
    }

    #[test]
    fn parse_system_profiler_empty_array_returns_none() {
        let json = r#"{"SPDisplaysDataType":[]}"#;
        assert!(parse_system_profiler_output(json).is_none());
    }

    #[test]
    fn parse_system_profiler_malformed_returns_none() {
        assert!(parse_system_profiler_output("not json").is_none());
        assert!(parse_system_profiler_output(r#"{"OtherKey":[]}"#).is_none());
    }

    // ── top-level classifier ──────────────────────────────────────

    #[test]
    fn classify_prefers_nvidia_when_present() {
        let r = classify_from_subprocess(
            Some("RTX 4090, 24000"),
            Some("device,vram_total_b\nrx,8589934592"),
            Some(r#"{"SPDisplaysDataType":[{"_name":"M1"}]}"#),
        );
        assert_eq!(r.kind, GpuKind::Cuda);
    }

    #[test]
    fn classify_falls_back_to_rocm_when_no_nvidia() {
        let r = classify_from_subprocess(None, Some("device,vram_total_b\nrx,17179869184"), None);
        assert_eq!(r.kind, GpuKind::Rocm);
    }

    #[test]
    fn classify_falls_back_to_metal_when_no_other_gpu() {
        let r = classify_from_subprocess(
            None,
            None,
            Some(r#"{"SPDisplaysDataType":[{"_name":"M1"}]}"#),
        );
        assert_eq!(r.kind, GpuKind::Metal);
    }

    #[test]
    fn classify_falls_back_to_cpu_when_all_probes_silent() {
        let r = classify_from_subprocess(None, None, None);
        assert_eq!(r.kind, GpuKind::Cpu);
        assert!(r.vram_mib.is_none());
    }

    #[test]
    fn classify_skips_unparsable_nvidia_smi_and_uses_rocm() {
        let r = classify_from_subprocess(
            Some("garbage stdout"),
            Some("device,vram_total_b\nrx,8589934592"),
            None,
        );
        assert_eq!(r.kind, GpuKind::Rocm);
    }

    #[test]
    fn probe_cmd_nonexistent_command_returns_none() {
        // spawn() fails → early None, no thread spawned.
        assert_eq!(
            probe_cmd("definitely-not-a-real-binary-xyz", &[], std::time::Duration::from_millis(500)),
            None
        );
    }

    #[test]
    fn probe_cmd_timeout_does_not_block_caller() {
        // GR-082 regression: a hung child must NOT block past the timeout, and
        // must be killed (not leaked). Use a platform sleep that runs far longer
        // than the timeout; the call must return None promptly.
        #[cfg(windows)]
        let (cmd, args): (&str, &[&str]) = ("ping", &["127.0.0.1", "-n", "20"]);
        #[cfg(not(windows))]
        let (cmd, args): (&str, &[&str]) = ("sleep", &["20"]);

        let start = std::time::Instant::now();
        let out = probe_cmd(cmd, args, std::time::Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert_eq!(out, None, "timed-out probe must return None");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "probe blocked for {elapsed:?} — timeout/kill did not unblock the caller"
        );
    }
}
