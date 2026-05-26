//! W-01 — central detection report aggregator.
//!
//! The wizard runs a battery of probes (Docker / npm / GPU / CLI
//! versions / disk space) before recommending an install profile.
//! Today each installer module ships its own probe surface; this
//! module aggregates them into one [`DetectReport`] that the
//! [`super::n8n`] / [`super::paperless`] / future [`super::gpu`]
//! modules contribute to.
//!
//! Cached at `~/.neoth/detect_cache.json` with a 24 h TTL —
//! re-running probes on every wizard step is wasteful + spawns
//! visible subprocess flicker. The wizard:
//!
//!   1. Tries `load_cache(home, now_unix)` — fresh hit short-circuits.
//!   2. On miss → [`probe_all()`] (parallel via `tokio::join!`).
//!   3. Persists via `save_cache(home, &report, now_unix)`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Cache TTL — 24 hours. Operators expecting NEOTH to pick up a
/// freshly installed Docker without re-running the wizard step can
/// pass `--no-cache` to `neoth init` (CLI surface lands when the
/// wizard step expansion ships).
pub const DETECT_CACHE_TTL_SECS: u64 = 24 * 3600;

/// Aggregate of every probe outcome the wizard reads. Each field
/// is `Option<...>` so a partial result (one probe failed) still
/// serialises cleanly without truncating the rest of the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectReport {
    /// Unix seconds of the probe run that produced this report.
    pub probed_at_unix: u64,
    pub docker_version: Option<String>,
    pub docker_compose_version: Option<String>,
    pub docker_compose_legacy_version: Option<String>,
    pub npm_version: Option<String>,
    pub node_version: Option<String>,
    pub git_version: Option<String>,
    pub ffmpeg_version: Option<String>,
    #[serde(default)]
    pub gpu: Option<super::gpu::GpuReport>,
    #[serde(default)]
    pub disk_free_bytes: Option<u64>,
}

impl DetectReport {
    /// True when this report is older than `DETECT_CACHE_TTL_SECS`
    /// vs `now_unix`. A future-dated `probed_at_unix` (clock skew)
    /// is treated as fresh — the worst case is one redundant probe.
    pub fn is_stale(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.probed_at_unix) > DETECT_CACHE_TTL_SECS
    }

    /// Operator-facing pretty rendering — used by the wizard
    /// "what did we find?" panel + `neoth doctor`.
    pub fn render_summary(&self) -> String {
        let mut out = String::new();
        out.push_str("Detection summary:\n");
        out.push_str(&line("docker", &self.docker_version));
        out.push_str(&line("docker compose", &self.docker_compose_version));
        out.push_str(&line(
            "docker-compose (legacy)",
            &self.docker_compose_legacy_version,
        ));
        out.push_str(&line("npm", &self.npm_version));
        out.push_str(&line("node", &self.node_version));
        out.push_str(&line("git", &self.git_version));
        out.push_str(&line("ffmpeg", &self.ffmpeg_version));
        match &self.gpu {
            Some(g) => out.push_str(&format!(
                "  gpu: {} ({} MiB VRAM)\n",
                g.kind.as_str(),
                g.vram_mib.unwrap_or(0),
            )),
            None => out.push_str("  gpu: (not detected)\n"),
        }
        if let Some(free) = self.disk_free_bytes {
            out.push_str(&format!(
                "  disk free: {} GiB\n",
                free / 1024 / 1024 / 1024
            ));
        }
        out
    }
}

fn line(name: &str, value: &Option<String>) -> String {
    match value {
        Some(v) => format!("  {name}: {v}\n"),
        None => format!("  {name}: (not detected)\n"),
    }
}

/// Path to the cache file under the NEOTH home dir.
pub fn cache_path(home: &Path) -> PathBuf {
    home.join("detect_cache.json")
}

/// Save the report to the cache. Atomic `.tmp` + rename so a
/// concurrent reader never sees a partial JSON.
pub fn save_cache(home: &Path, report: &DetectReport) -> std::io::Result<PathBuf> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    fs::create_dir_all(home)?;
    let path = cache_path(home);
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&body)?;
        f.flush()?;
    }
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Load + freshness-check the cached report. Returns `None` for
/// missing / malformed / stale entries — the wizard's signal to
/// re-probe.
pub fn load_cache(home: &Path, now_unix: u64) -> Option<DetectReport> {
    let body = std::fs::read_to_string(cache_path(home)).ok()?;
    let report: DetectReport = serde_json::from_str(&body).ok()?;
    if report.is_stale(now_unix) {
        return None;
    }
    Some(report)
}

/// Bridge call to run every probe in parallel and build the
/// report. Real implementation lands once a tokio runtime + the
/// per-installer probe fns are wired; the unit-test path here
/// exercises the aggregation shape with operator-supplied mock
/// values.
pub fn assemble_report(
    probed_at_unix: u64,
    docker_version: Option<String>,
    docker_compose_version: Option<String>,
    docker_compose_legacy_version: Option<String>,
    npm_version: Option<String>,
    node_version: Option<String>,
    git_version: Option<String>,
    ffmpeg_version: Option<String>,
    gpu: Option<super::gpu::GpuReport>,
    disk_free_bytes: Option<u64>,
) -> DetectReport {
    DetectReport {
        probed_at_unix,
        docker_version,
        docker_compose_version,
        docker_compose_legacy_version,
        npm_version,
        node_version,
        git_version,
        ffmpeg_version,
        gpu,
        disk_free_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::gpu::{GpuKind, GpuReport};

    fn fresh_report(ts: u64) -> DetectReport {
        DetectReport {
            probed_at_unix: ts,
            docker_version: Some("Docker version 25.0.0".into()),
            docker_compose_version: Some("Docker Compose version v2.24.0".into()),
            docker_compose_legacy_version: None,
            npm_version: Some("10.2.0".into()),
            node_version: Some("v20.10.0".into()),
            git_version: Some("git version 2.42.0".into()),
            ffmpeg_version: None,
            gpu: Some(GpuReport {
                kind: GpuKind::Cuda,
                vram_mib: Some(24_000),
                vendor: Some("NVIDIA".into()),
                name: Some("RTX 4090".into()),
            }),
            disk_free_bytes: Some(500 * 1024 * 1024 * 1024),
        }
    }

    #[test]
    fn ttl_constant_is_24h() {
        assert_eq!(DETECT_CACHE_TTL_SECS, 24 * 3600);
    }

    #[test]
    fn is_stale_false_within_ttl() {
        let r = fresh_report(1_000_000);
        assert!(!r.is_stale(1_000_000));
        assert!(!r.is_stale(1_000_000 + DETECT_CACHE_TTL_SECS));
    }

    #[test]
    fn is_stale_true_past_ttl() {
        let r = fresh_report(1_000_000);
        assert!(r.is_stale(1_000_000 + DETECT_CACHE_TTL_SECS + 1));
    }

    #[test]
    fn is_stale_false_for_future_clock_skew() {
        let r = fresh_report(2_000_000);
        // Cache was probed in the future (clock skew); treat as fresh.
        assert!(!r.is_stale(1_000_000));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let r = fresh_report(1_000_000);
        save_cache(home.path(), &r).unwrap();
        let loaded = load_cache(home.path(), 1_000_000).unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    fn load_missing_cache_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_cache(home.path(), 0).is_none());
    }

    #[test]
    fn load_stale_cache_returns_none() {
        let home = tempfile::tempdir().unwrap();
        let r = fresh_report(0);
        save_cache(home.path(), &r).unwrap();
        // Now is well past TTL.
        assert!(load_cache(home.path(), DETECT_CACHE_TTL_SECS * 2).is_none());
    }

    #[test]
    fn load_malformed_cache_returns_none() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(cache_path(home.path()), "not json").unwrap();
        assert!(load_cache(home.path(), 0).is_none());
    }

    #[test]
    fn save_uses_atomic_rename_no_tmp_leak() {
        let home = tempfile::tempdir().unwrap();
        save_cache(home.path(), &fresh_report(0)).unwrap();
        let tmp = home.path().join("detect_cache.json.tmp");
        assert!(!tmp.exists(), "tmp leaked: {tmp:?}");
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        save_cache(home.path(), &fresh_report(100)).unwrap();
        let mut second = fresh_report(200);
        second.docker_version = Some("Docker version 26.0.0".into());
        save_cache(home.path(), &second).unwrap();
        let loaded = load_cache(home.path(), 200).unwrap();
        assert_eq!(loaded.docker_version, Some("Docker version 26.0.0".into()));
    }

    #[test]
    fn assemble_report_carries_all_fields() {
        let r = assemble_report(
            42,
            Some("d".into()),
            Some("dc".into()),
            None,
            Some("n".into()),
            None,
            None,
            None,
            None,
            Some(1024),
        );
        assert_eq!(r.probed_at_unix, 42);
        assert_eq!(r.docker_version.as_deref(), Some("d"));
        assert_eq!(r.docker_compose_version.as_deref(), Some("dc"));
        assert!(r.docker_compose_legacy_version.is_none());
        assert_eq!(r.npm_version.as_deref(), Some("n"));
        assert!(r.gpu.is_none());
        assert_eq!(r.disk_free_bytes, Some(1024));
    }

    #[test]
    fn render_summary_lists_all_known_probes() {
        let r = fresh_report(0);
        let s = r.render_summary();
        assert!(s.contains("docker:"));
        assert!(s.contains("docker compose:"));
        assert!(s.contains("npm:"));
        assert!(s.contains("git:"));
        assert!(s.contains("gpu: cuda"));
        assert!(s.contains("disk free:"));
    }

    #[test]
    fn render_summary_shows_not_detected_for_missing_probes() {
        let mut r = fresh_report(0);
        r.ffmpeg_version = None;
        let s = r.render_summary();
        assert!(s.contains("ffmpeg: (not detected)"));
    }

    #[test]
    fn render_summary_no_gpu_when_absent() {
        let mut r = fresh_report(0);
        r.gpu = None;
        let s = r.render_summary();
        assert!(s.contains("gpu: (not detected)"));
    }
}
