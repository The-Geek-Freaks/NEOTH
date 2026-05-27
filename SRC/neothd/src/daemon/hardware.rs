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
    /// Whisper large-v3-turbo — the actual default the engine pulls.
    /// The previous `whisper_base` field was a stale name from the
    /// scaffold; field renamed to match `providers::whisper::DEFAULT_WHISPER_REPO`.
    pub whisper_large_v3_turbo: bool,
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

/// Run the probe. Always returns a populated report — every field has
/// a sensible default when detection fails (cpu=unknown, ram=0, etc.).
pub fn probe(neoth_home: &Path) -> HardwareReport {
    let cpu = probe_cpu();
    let memory = probe_memory();
    let accelerator = probe_acc();
    let binaries = probe_binaries();
    let cached_models = probe_cached_models(neoth_home);
    let disk = probe_disk(neoth_home);
    let recommended_qwen_repo = recommend_qwen(&cpu, &memory, &accelerator);
    // Approximate cache footprint for the curated model set. These
    // numbers are stable per model release; the wizard's disk-check
    // step uses them to warn about ENOSPC before the download starts.
    //   Qwen2.5-3B-Instruct  ~6.0 GiB f16
    //   whisper-large-v3-turbo ~1.6 GiB
    //   openai/clip-vit-base-patch32 ~0.6 GiB
    let estimated_full_cache_gib = 6.0 + 1.6 + 0.6;
    HardwareReport {
        cpu,
        memory,
        accelerator,
        binaries,
        cached_models,
        disk,
        recommended_qwen_repo,
        estimated_full_cache_gib,
    }
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

fn probe_cached_models(neoth_home: &Path) -> CachedModels {
    let models = neoth_home.join("models");
    CachedModels {
        qwen2_5_3b: models
            .join("Qwen-Qwen2.5-3B-Instruct")
            .join("model.safetensors")
            .exists(),
        qwen3_7b: models
            .join("Qwen-Qwen3-7B-Instruct")
            .join("model.safetensors")
            .exists(),
        // Engine pulls openai/whisper-large-v3-turbo (flattened repo
        // name = openai-whisper-large-v3-turbo). The previous probe
        // looked for `openai-whisper-base` which never matched the
        // real cache directory.
        whisper_large_v3_turbo: models
            .join("openai-whisper-large-v3-turbo")
            .join("model.safetensors")
            .exists(),
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
            "  Cached models: qwen2.5-3b={} qwen3-7b={} whisper-turbo={} clip-vit-b32={}",
            self.cached_models.qwen2_5_3b,
            self.cached_models.qwen3_7b,
            self.cached_models.whisper_large_v3_turbo,
            self.cached_models.clip_vit_b32,
        );
        let _ = writeln!(
            s,
            "  Disk:          {:.1} GiB free / {:.1} GiB total ({})",
            self.disk.home_available_gib(),
            self.disk.home_total_gib(),
            self.disk.home_mount,
        );
        let _ = writeln!(
            s,
            "  Full model cache: ~{:.1} GiB (qwen + whisper-turbo + clip)",
            self.estimated_full_cache_gib,
        );
        let _ = writeln!(s, "  Recommended Qwen: {}", self.recommended_qwen_repo);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn probe_returns_non_zero_cpu_and_memory_on_real_host() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path());
        assert!(report.cpu.logical_cores >= 1);
        assert!(report.memory.total_bytes > 0);
        // accelerator.picked is always one of the four known strings.
        let valid = ["cuda", "metal", "openvino", "cpu"];
        assert!(valid.contains(&report.accelerator.picked));
    }

    #[test]
    fn cached_models_all_false_on_empty_home() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path());
        assert!(!report.cached_models.qwen2_5_3b);
        assert!(!report.cached_models.qwen3_7b);
        assert!(!report.cached_models.whisper_large_v3_turbo);
        assert!(!report.cached_models.clip_vit_b32);
    }

    #[test]
    fn whisper_cache_check_targets_turbo_repo() {
        // Regression guard: the engine pulls openai/whisper-large-v3-turbo
        // (flattened to openai-whisper-large-v3-turbo). A stale check
        // against `openai-whisper-base` would silently report "not
        // cached" forever.
        let dir = tempdir().unwrap();
        let turbo = dir
            .path()
            .join("models")
            .join("openai-whisper-large-v3-turbo");
        std::fs::create_dir_all(&turbo).unwrap();
        std::fs::write(turbo.join("model.safetensors"), b"fake").unwrap();
        let report = probe(dir.path());
        assert!(report.cached_models.whisper_large_v3_turbo);
    }

    #[test]
    fn disk_info_is_populated_or_zero() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path());
        // Either we resolved a mount (total > 0) OR we fell back to
        // zeros — never panic, never NaN.
        let d = &report.disk;
        assert!(d.home_total_bytes >= d.home_available_bytes);
        assert!(!d.home_mount.is_empty());
    }

    #[test]
    fn estimated_full_cache_in_known_ballpark() {
        let dir = tempdir().unwrap();
        let report = probe(dir.path());
        // The hand-computed sum is 6.0 + 1.6 + 0.6 = 8.2 GiB. Catch
        // accidental constant drift.
        assert!(
            (report.estimated_full_cache_gib - 8.2).abs() < 0.1,
            "estimated cache footprint drifted: {}",
            report.estimated_full_cache_gib
        );
    }

    #[test]
    fn cached_models_true_when_safetensors_present() {
        let dir = tempdir().unwrap();
        let qwen_dir = dir.path().join("models").join("Qwen-Qwen2.5-3B-Instruct");
        std::fs::create_dir_all(&qwen_dir).unwrap();
        std::fs::write(qwen_dir.join("model.safetensors"), b"fake").unwrap();
        let report = probe(dir.path());
        assert!(report.cached_models.qwen2_5_3b);
        assert!(!report.cached_models.qwen3_7b);
        assert!(!report.cached_models.whisper_large_v3_turbo);
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
        let report = probe(dir.path());
        let s = report.render_summary();
        assert!(s.contains("CPU:"));
        assert!(s.contains("RAM:"));
        assert!(s.contains("Accelerator:"));
        assert!(s.contains("Binaries:"));
        assert!(s.contains("Cached models:"));
        assert!(s.contains("Recommended Qwen:"));
    }
}
