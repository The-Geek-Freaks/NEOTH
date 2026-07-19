//! Consolidated hardware probe — drives the onboarding wizard's "this
//! is what your machine can do" screen + dynamic defaults for model
//! sizes, ffmpeg subprocess concurrency, etc.
//!
//! Combines:
//!   - CPU: cores, brand string, frequency (via `sysinfo`)
//!   - RAM: total + available (via `sysinfo`)
//!   - Accelerator: existing `daemon::accelerator::probe()` (CUDA / Metal
//!     / OpenVINO / CPU)
//!   - External binaries: `ffmpeg` on PATH (for R-9 video pipeline)
//!   - Local model cache: detects whether Qwen/whisper/CLIP weights are
//!     already downloaded so the wizard doesn't promise a redundant ~3 GB
//!     download.
//!
//! Pure read — never writes anything. Safe to call from any context
//! (CLI, GUI, daemon status snapshot).

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use super::accelerator::{Accelerator, probe as probe_accelerator};

/// Top-level probe result. Sized for JSON serialisation so the GUI can
/// ingest it directly via `serde_json`.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HardwareReport {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub accelerator: AcceleratorInfo,
    pub binaries: ExternalBinaries,
    pub cached_models: CachedModels,
    pub disk: DiskInfo,
    /// Best-guess recommended Qwen variant given the operator's hardware.
    /// Operator may still pick anything in step 5; this is just the
    /// default we suggest. Format = HuggingFace repo identifier.
    pub recommended_qwen_repo: &'static str,
    /// Estimated GiB the operator would need to download to cache every
    /// model NEOTH currently knows about. Surfaced in the wizard so the
    /// disk check can warn before a 5 GiB download fails halfway.
    pub estimated_full_cache_gib: f64,
    /// SL-03 — LIVE GPU VRAM reading (used + total MiB) at probe time, via
    /// `nvidia-smi`/`rocm-smi`. `None` on a CPU-only host or when no GPU tool
    /// is on PATH. Distinct from `accelerator` (which is a static capability
    /// probe) — this is the moment-in-time utilisation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vram: Option<crate::daemon::resource_watch::VramReading>,
    /// GUI-HARDWARE-RESOURCES-01 — CPU aggregate utilization % (two-refresh
    /// sysinfo delta; ~200 ms added to probe latency). `None` on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_load_pct: Option<f32>,
    /// GUI-HARDWARE-RESOURCES-01 — GPU runtime metrics (utilization %,
    /// temperature °C, power draw W) from one `nvidia-smi` call. `None` on a
    /// CPU-only host or when `nvidia-smi` is not on PATH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_load: Option<GpuLoadReading>,
}

/// Best-effort GPU runtime metrics (first GPU only) from `nvidia-smi`.
/// `None` on a CPU-only host, non-NVIDIA GPU, or when `nvidia-smi` is absent.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct GpuLoadReading {
    /// Compute utilization percentage (0–100).
    pub util_pct: u8,
    /// Core temperature in degrees Celsius.
    pub temp_c: u8,
    /// Power draw in whole Watts.
    pub power_w: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CpuInfo {
    pub brand: String,
    pub logical_cores: usize,
    pub physical_cores: usize,
    pub frequency_mhz: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

impl MemoryInfo {
    /// Convenience for the GUI: GiB rounded to one decimal.
    pub fn total_gib(&self) -> f64 {
        (self.total_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    }
    pub fn available_gib(&self) -> f64 {
        (self.available_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AcceleratorInfo {
    pub picked: &'static str,
    pub cuda: bool,
    pub metal: bool,
    pub openvino: bool,
    /// True when the picked accelerator is something other than plain CPU.
    pub has_gpu_path: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ExternalBinaries {
    pub ffmpeg: bool,
    pub claude_cli: bool,
    /// `agy` binary detection (Antigravity CLI, gemini-cli successor
    /// per 2026-05-19 transition). The serde field name keeps the
    /// snapshot schema stable for downstream JSON consumers (doctor,
    /// neothd-gui) that read older audit reports too — old reports
    /// with `"gemini_cli": true` simply read as "no agy detected"
    /// going forward.
    #[serde(rename = "agy_cli", alias = "gemini_cli")]
    pub antigravity_cli: bool,
    pub codex_cli: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CachedModels {
    pub qwen2_5_3b: bool,
    pub qwen3_7b: bool,
    /// Legacy serialized field retained for snapshot compatibility. Canonical
    /// STT no longer probes a hardcoded turbo repository, so this stays false.
    pub whisper_large_v3_turbo: bool,
    /// Whether the effective configured local STT target is complete in its
    /// canonical runtime cache.
    pub whisper_configured: bool,
    /// Exact repository checked by `whisper_configured`.
    pub configured_whisper_repo: String,
    /// Effective configured STT backend checked by `whisper_configured`.
    pub configured_whisper_backend: String,
    /// Exact runtime cache directory checked by `whisper_configured`.
    pub configured_whisper_cache: String,
    /// Structural cache state shared with the runtime, models CLI and doctor.
    pub configured_whisper_health: String,
    /// Actionable reason no local Whisper target exists (cloud primary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_whisper_error: Option<String>,
    pub clip_vit_b32: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DiskInfo {
    /// Bytes available on the partition that holds `~/.neoth/`.
    pub home_available_bytes: u64,
    /// Total bytes on that partition.
    pub home_total_bytes: u64,
    /// Operator-readable mount source path (where sysinfo found the
    /// disk that backs `neoth_home`).
    pub home_mount: String,
}

impl DiskInfo {
    pub fn home_available_gib(&self) -> f64 {
        (self.home_available_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    }
    pub fn home_total_gib(&self) -> f64 {
        (self.home_total_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    }
}

/// Run the probe. Hardware detection itself remains best-effort, but an
/// existing invalid operator config is surfaced because it selects the STT
/// model/cache targets reported to the operator.
pub fn probe(neoth_home: &Path) -> Result<HardwareReport> {
    let cpu = probe_cpu();
    let memory = probe_memory();
    let accelerator = probe_acc();
    let binaries = probe_binaries();
    let config =
        crate::config::FreedomConfig::load_from_path_or_default(&neoth_home.join("freedom.yaml"))?;
    let whisper_size = config.media.stt.model_size;
    let whisper_target = crate::media::stt_provider::resolve_local_whisper_target(
        neoth_home,
        config.media.stt.primary,
        whisper_size,
    );
    let cached_models = probe_cached_models(neoth_home, config.media.stt.primary, whisper_target);
    let disk = probe_disk(neoth_home);
    let recommended_qwen_repo = recommend_qwen(&cpu, &memory, &accelerator);
    // Approximate cache footprint for the curated model set. These
    // numbers are stable per model release; the wizard's disk-check
    // step uses them to warn about ENOSPC before the download starts.
    //   Qwen2.5-3B-Instruct  ~6.0 GiB f16
    //   configured Whisper size (see WhisperModelSize::approx_size_mb)
    //   openai/clip-vit-base-patch32 ~0.6 GiB
    let estimated_full_cache_gib = 6.0 + f64::from(whisper_size.approx_size_mb()) / 1024.0 + 0.6;
    // SL-03 — best-effort LIVE VRAM read (nvidia-smi/rocm-smi). None on a
    // CPU-only host or when no GPU tool is on PATH; never fails the probe.
    let vram = crate::daemon::resource_watch::read_gpu_vram();
    // GUI-HARDWARE-RESOURCES-01 — CPU load adds ~200 ms (two-refresh delta).
    // GPU load is one short nvidia-smi subprocess. Both are best-effort.
    let cpu_load_pct = probe_cpu_load();
    let gpu_load = probe_gpu_load();
    Ok(HardwareReport {
        cpu,
        memory,
        accelerator,
        binaries,
        cached_models,
        disk,
        recommended_qwen_repo,
        estimated_full_cache_gib,
        vram,
        cpu_load_pct,
        gpu_load,
    })
}

fn probe_cpu() -> CpuInfo {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_cpu_all();
    let logical_cores = sys.cpus().len();
    let physical_cores = sys.physical_core_count().unwrap_or(logical_cores);
    let (brand, frequency_mhz) = match sys.cpus().first() {
        Some(c) => (c.brand().to_string(), c.frequency()),
        None => ("unknown".to_string(), 0),
    };
    CpuInfo {
        brand,
        logical_cores,
        physical_cores,
        frequency_mhz,
    }
}

fn probe_memory() -> MemoryInfo {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    MemoryInfo {
        total_bytes: sys.total_memory(),
        available_bytes: sys.available_memory(),
    }
}

fn probe_acc() -> AcceleratorInfo {
    let p = probe_accelerator();
    AcceleratorInfo {
        picked: p.picked.as_str(),
        cuda: p.cuda,
        metal: p.metal,
        openvino: p.openvino,
        has_gpu_path: p.picked != Accelerator::Cpu,
    }
}

fn probe_binaries() -> ExternalBinaries {
    ExternalBinaries {
        ffmpeg: is_on_path("ffmpeg"),
        claude_cli: is_on_path("claude"),
        antigravity_cli: is_on_path("agy"),
        codex_cli: is_on_path("codex"),
    }
}

fn is_on_path(name: &str) -> bool {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let Some(path_env) = std::env::var_os("PATH") else {
        return false;
    };
    for entry in std::env::split_paths(&path_env) {
        if entry.join(&exe).exists() {
            return true;
        }
    }
    false
}

fn probe_cached_models(
    neoth_home: &Path,
    configured_backend: crate::media::stt_dispatch::SttProvider,
    whisper_target: Result<
        crate::media::stt_provider::LocalWhisperTarget,
        crate::media::stt_provider::SttFactoryError,
    >,
) -> CachedModels {
    let models = neoth_home.join("models");
    let (
        whisper_configured,
        configured_whisper_repo,
        configured_whisper_cache,
        configured_whisper_health,
        error,
    ) = match whisper_target {
        Ok(target) => {
            let health = target.cache_health();
            let error = matches!(
                &health,
                crate::media::model_manager::CacheHealth::Corrupt { .. }
            )
            .then(|| health.to_string());
            (
                health.is_ready(),
                target.model_id().to_string(),
                target.cache_path().display().to_string(),
                health.label().to_string(),
                error,
            )
        }
        Err(error) => (
            false,
            String::new(),
            String::new(),
            "unavailable".to_string(),
            Some(error.to_string()),
        ),
    };
    CachedModels {
        qwen2_5_3b: crate::providers::local_qwen::validate_runtime_artifacts_at(
            &crate::providers::local_qwen::cache_dir_at(
                neoth_home,
                crate::providers::local_qwen::DEFAULT_HF_REPO,
            ),
            false,
        )
        .is_ok(),
        qwen3_7b: models
            .join("Qwen-Qwen3-7B-Instruct")
            .join("model.safetensors")
            .exists(),
        whisper_large_v3_turbo: false,
        whisper_configured,
        configured_whisper_repo,
        configured_whisper_backend: configured_backend.as_str().to_string(),
        configured_whisper_cache,
        configured_whisper_health,
        configured_whisper_error: error,
        clip_vit_b32: models
            .join("openai-clip-vit-base-patch32")
            .join("model.safetensors")
            .exists(),
    }
}

/// Available + total bytes on the disk holding `~/.neoth/`. sysinfo
/// gives us a per-mount list; we walk it and pick the longest mount
/// prefix that matches `neoth_home`. Falls back to zeros when no
/// candidate matches (containers with overlayfs, weird remounts) —
/// the wizard handles zeros as "can't tell, don't warn".
///
/// On Windows the prefix comparison is case-insensitive — sysinfo may
/// return `C:\` while `PathBuf` resolves to `c:\users\...` depending
/// on environment, and a strict case-sensitive match silently dropped
/// the disk info on those hosts.
fn probe_disk(neoth_home: &Path) -> DiskInfo {
    use sysinfo::Disks;
    let home_str = neoth_home.to_string_lossy().to_string();
    let home_cmp = disk_prefix_normalize(&home_str);
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<&sysinfo::Disk> = None;
    let mut best_len = 0usize;
    for disk in disks.list() {
        let mp = disk.mount_point().to_string_lossy().into_owned();
        let mp_cmp = disk_prefix_normalize(&mp);
        if home_cmp.starts_with(&mp_cmp) && mp_cmp.len() > best_len {
            best_len = mp_cmp.len();
            best = Some(disk);
        }
    }
    match best {
        Some(d) => DiskInfo {
            home_available_bytes: d.available_space(),
            home_total_bytes: d.total_space(),
            home_mount: d.mount_point().to_string_lossy().into_owned(),
        },
        None => DiskInfo {
            home_available_bytes: 0,
            home_total_bytes: 0,
            home_mount: home_str,
        },
    }
}

#[cfg(windows)]
fn disk_prefix_normalize(s: &str) -> String {
    s.to_lowercase()
}

#[cfg(not(windows))]
fn disk_prefix_normalize(s: &str) -> String {
    s.to_string()
}

/// CPU aggregate utilization over a ~200 ms sampling window (two sysinfo
/// refreshes required for a valid delta). `None` when the probe fails.
fn probe_cpu_load() -> Option<f32> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_cpu_usage();
    // The delta between two refreshes gives the actual utilization %;
    // a single refresh always returns 0 on the first call.
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu_usage();
    let pct = sys.global_cpu_usage();
    if pct.is_nan() { None } else { Some(pct) }
}

/// GPU runtime metrics from one `nvidia-smi` call. `None` on any failure
/// (binary absent, non-zero exit, non-NVIDIA host, parse miss). Never panics.
fn probe_gpu_load() -> Option<GpuLoadReading> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=utilization.gpu,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_nvidia_smi_load(&String::from_utf8_lossy(&out.stdout))
}

/// Parse one CSV line from
/// `nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,power.draw
/// --format=csv,noheader,nounits`, e.g. `"41, 62, 118.45"`.
/// `None` on a malformed / empty / single-field line.
pub(crate) fn parse_nvidia_smi_load(text: &str) -> Option<GpuLoadReading> {
    let line = text.lines().next()?.trim();
    let mut parts = line.split(',').map(str::trim);
    let util_pct = parts.next()?.parse::<f64>().ok()?.round() as u8;
    let temp_c = parts.next()?.parse::<f64>().ok()?.round() as u8;
    let power_w = parts.next()?.parse::<f64>().ok()?.round() as u32;
    Some(GpuLoadReading {
        util_pct,
        temp_c,
        power_w,
    })
}

/// Pick a default Qwen variant. Rules:
///   - ≥ 24 GiB RAM + GPU → recommend 14B (heavy but operator can afford)
///   - ≥ 16 GiB RAM       → recommend 7B
///   - everything else    → 3B (the existing default)
fn recommend_qwen(_cpu: &CpuInfo, mem: &MemoryInfo, acc: &AcceleratorInfo) -> &'static str {
    let gib = mem.total_gib();
    if gib >= 24.0 && acc.has_gpu_path {
        "Qwen/Qwen2.5-14B-Instruct"
    } else if gib >= 16.0 {
        "Qwen/Qwen2.5-7B-Instruct"
    } else {
        "Qwen/Qwen2.5-3B-Instruct"
    }
}

impl HardwareReport {
    /// Operator-readable one-screen summary. Mirrors what the GUI
    /// renders inside the welcome step.
    pub fn render_summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Hardware probe:");
        let _ = writeln!(
            s,
            "  CPU:           {} ({} logical / {} physical, {} MHz)",
            self.cpu.brand, self.cpu.logical_cores, self.cpu.physical_cores, self.cpu.frequency_mhz,
        );
        let _ = writeln!(
            s,
            "  RAM:           {:.1} GiB total / {:.1} GiB available",
            self.memory.total_gib(),
            self.memory.available_gib(),
        );
        let _ = writeln!(
            s,
            "  Accelerator:   {} (cuda={} metal={} openvino={})",
            self.accelerator.picked,
            self.accelerator.cuda,
            self.accelerator.metal,
            self.accelerator.openvino,
        );
        let _ = writeln!(
            s,
            "  Binaries:      ffmpeg={} claude={} agy={} codex={}",
            self.binaries.ffmpeg,
            self.binaries.claude_cli,
            self.binaries.antigravity_cli,
            self.binaries.codex_cli,
        );
        let _ = writeln!(
            s,
            "  Cached models: qwen2.5-3b={} qwen3-7b={} whisper={} \
             (health={} backend={} repo={} cache={}) clip-vit-b32={}",
            self.cached_models.qwen2_5_3b,
            self.cached_models.qwen3_7b,
            self.cached_models.whisper_configured,
            self.cached_models.configured_whisper_health,
            self.cached_models.configured_whisper_backend,
            self.cached_models.configured_whisper_repo,
            self.cached_models.configured_whisper_cache,
            self.cached_models.clip_vit_b32,
        );
        if let Some(error) = &self.cached_models.configured_whisper_error {
            let _ = writeln!(
                s,
                "  Whisper target: {} ({error})",
                self.cached_models.configured_whisper_health
            );
        }
        let _ = writeln!(
            s,
            "  Disk:          {:.1} GiB free / {:.1} GiB total ({})",
            self.disk.home_available_gib(),
            self.disk.home_total_gib(),
            self.disk.home_mount,
        );
        let _ = writeln!(
            s,
            "  Full model cache: ~{:.1} GiB (qwen + configured whisper + clip)",
            self.estimated_full_cache_gib,
        );
        let _ = writeln!(s, "  Recommended Qwen: {}", self.recommended_qwen_repo);
        // SL-03 — live VRAM line when a GPU tool reported a reading.
        if let Some(v) = self.vram {
            let _ = writeln!(
                s,
                "  GPU VRAM:      {} / {} MiB ({:.0}% used)",
                v.used_mib,
                v.total_mib,
                v.pressure_pct(),
            );
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn materialize_candle_cache(models_root: &Path, repo: &str) -> PathBuf {
        crate::providers::whisper::materialize_structural_test_cache(models_root, repo).unwrap()
    }

    fn materialize_faster_cache(cache_root: &Path, repo: &str) -> PathBuf {
        crate::media::stt_provider::materialize_structural_faster_whisper_test_cache(
            cache_root, repo,
        )
        .unwrap();
        cache_root.join(format!("models--{}", repo.replace('/', "--")))
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn render_summary_shows_vram_line_only_when_present() {
        use crate::daemon::resource_watch::VramReading;
        let dir = tempdir().unwrap();
        let mut report = probe(dir.path()).unwrap();
        // With a reading → a GPU VRAM line is present + json carries `vram`.
        report.vram = Some(VramReading {
            used_mib: 4000,
            total_mib: 8000,
        });
        let summary = report.render_summary();
        assert!(
            summary.contains("GPU VRAM:      4000 / 8000 MiB (50% used)"),
            "got: {summary}"
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"vram\""));
        assert!(json.contains("\"used_mib\":4000"));
        // Without a reading → no VRAM line + the field is omitted from json.
        report.vram = None;
        assert!(!report.render_summary().contains("GPU VRAM"));
        assert!(!serde_json::to_string(&report).unwrap().contains("\"vram\""));
    }

    #[test]
    fn probe_returns_non_zero_cpu_and_memory_on_real_host() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path()).unwrap();
        assert!(report.cpu.logical_cores >= 1);
        assert!(report.memory.total_bytes > 0);
        // accelerator.picked is always one of the four known strings.
        let valid = ["cuda", "metal", "openvino", "cpu"];
        assert!(valid.contains(&report.accelerator.picked));
    }

    #[test]
    fn probe_rejects_malformed_existing_config() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml"), "media: [unterminated\n").unwrap();

        let error = probe(dir.path()).unwrap_err();

        assert!(format!("{error:#}").contains("parse YAML"));
    }

    #[test]
    fn cached_models_all_false_on_empty_home() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path()).unwrap();
        assert!(!report.cached_models.qwen2_5_3b);
        assert!(!report.cached_models.qwen3_7b);
        assert!(!report.cached_models.whisper_large_v3_turbo);
        assert!(!report.cached_models.whisper_configured);
        assert_eq!(
            report.cached_models.configured_whisper_repo,
            "openai/whisper-base"
        );
        assert_eq!(
            report.cached_models.configured_whisper_backend,
            "candle_whisper_local"
        );
        assert_eq!(
            report.cached_models.configured_whisper_cache,
            dir.path()
                .join("models")
                .join("openai-whisper-base")
                .display()
                .to_string()
        );
        assert_eq!(report.cached_models.configured_whisper_health, "missing");
        assert!(report.cached_models.configured_whisper_error.is_none());
        assert!(!report.cached_models.clip_vit_b32);
    }

    #[test]
    fn whisper_cache_check_targets_configured_stt_repo() {
        // No freedom.yaml means the serde default (Base). The hardware surface
        // must check the same cache as the canonical STT factory and models CLI.
        let dir = tempdir().unwrap();
        let configured =
            materialize_candle_cache(&dir.path().join("models"), "openai/whisper-base");
        let report = probe(dir.path()).unwrap();
        assert!(report.cached_models.whisper_configured);
        assert_eq!(
            report.cached_models.configured_whisper_repo,
            "openai/whisper-base"
        );
        assert_eq!(
            report.cached_models.configured_whisper_backend,
            "candle_whisper_local"
        );
        assert_eq!(
            report.cached_models.configured_whisper_cache,
            configured.display().to_string()
        );
        assert_eq!(report.cached_models.configured_whisper_health, "ready");
        assert!(report.cached_models.configured_whisper_error.is_none());
        assert!(!report.cached_models.whisper_large_v3_turbo);
    }

    #[test]
    fn hardware_uses_faster_whisper_runtime_target_and_neoth_owned_default_cache() {
        let dir = tempdir().unwrap();
        let _env = crate::test_env::lock();
        let _hub = EnvGuard::remove("HUGGINGFACE_HUB_CACHE");
        let _hf_home = EnvGuard::remove("HF_HOME");
        let _xdg = EnvGuard::remove("XDG_CACHE_HOME");
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "media:\n  stt:\n    primary: faster_whisper_local\n    model_size: small\n",
        )
        .unwrap();
        let cache_root = dir.path().join("cache").join("huggingface").join("hub");
        let cache = materialize_faster_cache(&cache_root, "Systran/faster-whisper-small");

        let report = probe(dir.path()).unwrap();

        assert!(report.cached_models.whisper_configured);
        assert_eq!(
            report.cached_models.configured_whisper_backend,
            "faster_whisper_local"
        );
        assert_eq!(
            report.cached_models.configured_whisper_repo,
            "Systran/faster-whisper-small"
        );
        assert_eq!(
            report.cached_models.configured_whisper_cache,
            cache.display().to_string()
        );
        assert_eq!(report.cached_models.configured_whisper_health, "ready");
        assert!(report.cached_models.configured_whisper_error.is_none());
        assert!(!report.cached_models.whisper_large_v3_turbo);
    }

    #[test]
    fn hardware_reports_actionable_non_local_whisper_primary() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "media:\n  stt:\n    primary: openai_whisper_api\n",
        )
        .unwrap();

        let report = probe(dir.path()).unwrap();

        assert!(!report.cached_models.whisper_configured);
        assert_eq!(
            report.cached_models.configured_whisper_backend,
            "openai_whisper_api"
        );
        assert!(report.cached_models.configured_whisper_repo.is_empty());
        assert!(report.cached_models.configured_whisper_cache.is_empty());
        assert_eq!(
            report.cached_models.configured_whisper_health,
            "unavailable"
        );
        let error = report
            .cached_models
            .configured_whisper_error
            .as_deref()
            .unwrap();
        assert!(error.contains("no managed local Whisper model"));
        assert!(
            report
                .render_summary()
                .contains("Whisper target: unavailable")
        );
    }

    #[test]
    fn disk_info_is_populated_or_zero() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path()).unwrap();
        // Either we resolved a mount (total > 0) OR we fell back to
        // zeros — never panic, never NaN.
        let d = &report.disk;
        assert!(d.home_total_bytes >= d.home_available_bytes);
        assert!(!d.home_mount.is_empty());
    }

    #[test]
    fn estimated_full_cache_in_known_ballpark() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path()).unwrap();
        let expected = 6.0
            + f64::from(crate::media::stt_dispatch::WhisperModelSize::Base.approx_size_mb())
                / 1024.0
            + 0.6;
        assert!(
            (report.estimated_full_cache_gib - expected).abs() < 0.01,
            "estimated cache footprint drifted: {}",
            report.estimated_full_cache_gib
        );
    }

    #[test]
    fn qwen_cache_is_not_ready_with_only_a_safetensors_filename() {
        let dir = tempdir().unwrap();
        let qwen_dir = dir.path().join("models").join("Qwen-Qwen2.5-3B-Instruct");
        std::fs::create_dir_all(&qwen_dir).unwrap();
        std::fs::write(qwen_dir.join("model.safetensors"), b"fake").unwrap();
        let report = probe(dir.path()).unwrap();
        assert!(!report.cached_models.qwen2_5_3b);
        assert!(!report.cached_models.qwen3_7b);
        assert!(!report.cached_models.whisper_large_v3_turbo);
        assert!(!report.cached_models.whisper_configured);
    }

    #[test]
    fn hardware_does_not_report_corrupt_whisper_cache_as_cached() {
        let dir = tempdir().unwrap();
        let cache = materialize_candle_cache(&dir.path().join("models"), "openai/whisper-base");
        std::fs::write(cache.join("config.json"), b"not-json").unwrap();

        let report = probe(dir.path()).unwrap();

        assert!(!report.cached_models.whisper_configured);
        assert_eq!(report.cached_models.configured_whisper_health, "corrupt");
        assert!(
            report
                .cached_models
                .configured_whisper_error
                .as_deref()
                .is_some_and(|error| error.contains("config.json"))
        );
    }

    #[test]
    fn recommend_qwen_picks_3b_on_low_ram_host() {
        let cpu = CpuInfo {
            brand: "x".into(),
            logical_cores: 4,
            physical_cores: 4,
            frequency_mhz: 0,
        };
        let mem = MemoryInfo {
            total_bytes: 8 * 1024 * 1024 * 1024,
            available_bytes: 4 * 1024 * 1024 * 1024,
        };
        let acc = AcceleratorInfo {
            picked: "cpu",
            cuda: false,
            metal: false,
            openvino: false,
            has_gpu_path: false,
        };
        assert_eq!(recommend_qwen(&cpu, &mem, &acc), "Qwen/Qwen2.5-3B-Instruct");
    }

    #[test]
    fn recommend_qwen_picks_7b_on_mid_ram_no_gpu_host() {
        let cpu = CpuInfo {
            brand: "x".into(),
            logical_cores: 8,
            physical_cores: 8,
            frequency_mhz: 0,
        };
        let mem = MemoryInfo {
            total_bytes: 20 * 1024 * 1024 * 1024,
            available_bytes: 12 * 1024 * 1024 * 1024,
        };
        let acc = AcceleratorInfo {
            picked: "cpu",
            cuda: false,
            metal: false,
            openvino: false,
            has_gpu_path: false,
        };
        assert_eq!(recommend_qwen(&cpu, &mem, &acc), "Qwen/Qwen2.5-7B-Instruct");
    }

    #[test]
    fn recommend_qwen_picks_14b_on_big_ram_plus_gpu() {
        let cpu = CpuInfo {
            brand: "x".into(),
            logical_cores: 16,
            physical_cores: 16,
            frequency_mhz: 0,
        };
        let mem = MemoryInfo {
            total_bytes: 32 * 1024 * 1024 * 1024,
            available_bytes: 24 * 1024 * 1024 * 1024,
        };
        let acc = AcceleratorInfo {
            picked: "cuda",
            cuda: true,
            metal: false,
            openvino: false,
            has_gpu_path: true,
        };
        assert_eq!(
            recommend_qwen(&cpu, &mem, &acc),
            "Qwen/Qwen2.5-14B-Instruct"
        );
    }

    #[test]
    fn render_summary_includes_every_section() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path()).unwrap();
        let s = report.render_summary();
        assert!(s.contains("CPU:"));
        assert!(s.contains("RAM:"));
        assert!(s.contains("Accelerator:"));
        assert!(s.contains("Binaries:"));
        assert!(s.contains("Cached models:"));
        assert!(s.contains("Recommended Qwen:"));
    }

    // ── GUI-HARDWARE-RESOURCES-01: parse_nvidia_smi_load ─────────────────

    #[test]
    fn parse_nvidia_smi_load_valid_line() {
        // Typical output: "41, 62, 118.45"
        let r = parse_nvidia_smi_load("41, 62, 118.45").unwrap();
        assert_eq!(r.util_pct, 41);
        assert_eq!(r.temp_c, 62);
        assert_eq!(r.power_w, 118);
    }

    #[test]
    fn parse_nvidia_smi_load_rounds_power() {
        // 118.55 → 119 W (round, not truncate).
        let r = parse_nvidia_smi_load("10, 55, 118.55").unwrap();
        assert_eq!(r.power_w, 119);
    }

    #[test]
    fn parse_nvidia_smi_load_first_line_wins() {
        // When output has multiple lines (multi-GPU), only the first is used.
        let r = parse_nvidia_smi_load("30, 70, 200.0\n80, 90, 300.0").unwrap();
        assert_eq!(r.util_pct, 30);
    }

    #[test]
    fn parse_nvidia_smi_load_returns_none_on_garbage() {
        assert!(parse_nvidia_smi_load("").is_none());
        assert!(parse_nvidia_smi_load("N/A, N/A, N/A").is_none());
        assert!(parse_nvidia_smi_load("only-one-field").is_none());
    }

    #[test]
    fn parse_nvidia_smi_load_returns_none_on_missing_third_field() {
        // Two fields — power_w is missing.
        assert!(parse_nvidia_smi_load("41, 62").is_none());
    }
}
