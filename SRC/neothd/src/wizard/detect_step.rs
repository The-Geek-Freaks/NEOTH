//! W-04 — wizard detect step.
//!
//! Orchestrates the W-01 system probes + W-08 `0xD5 DETECT_COMPLETE`
//! frame emission. The wizard's step-2 entry calls
//! [`run_detect_step`] with an operator-provided `now_unix` + the
//! NEOTH home dir; on return the operator sees the `DetectReport`
//! summary and the wizard moves to step 3 (recommend).
//!
//! ## Behaviour
//!
//! 1. Try `installers::detect::load_cache(home, now)`. Fresh hit
//!    → return that report verbatim, skip probes, skip frame
//!    (operator re-ran the wizard within the 24h TTL — we don't
//!    spam audit with duplicate detects).
//! 2. Miss → build report via [`DetectStepInputs`] (caller
//!    supplies the live probe results; the orchestrator stays
//!    pure-fn so tests don't spawn subprocesses).
//! 3. Save to cache atomically.
//! 4. Build the `DetectCompletePayload` + return it for the WAL
//!    emit-site to write the 0xD5 frame.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::installers::detect::{
    assemble_report, load_cache, save_cache, DetectReport,
};
use crate::installers::gpu::GpuReport;
use crate::wal::payloads_w08::DetectCompletePayload;

/// Pre-computed probe outputs the wizard step hands to the
/// orchestrator. Tests construct this directly; production code
/// builds it from the per-installer `check_*` fns running in
/// parallel via `tokio::join!`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectStepInputs {
    pub docker_version: Option<String>,
    pub docker_compose_version: Option<String>,
    pub docker_compose_legacy_version: Option<String>,
    pub npm_version: Option<String>,
    pub node_version: Option<String>,
    pub git_version: Option<String>,
    pub ffmpeg_version: Option<String>,
    pub gpu: Option<GpuReport>,
    pub disk_free_bytes: Option<u64>,
}

/// Outcome of one detect-step invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectStepOutcome {
    pub report: DetectReport,
    /// `true` when this run produced a fresh report (probes ran +
    /// cache was written). `false` when the cache short-circuit
    /// hit + no probes ran + no WAL frame should be emitted.
    pub probed_now: bool,
    /// Payload the WAL emit-site writes as the 0xD5 frame body.
    /// Empty when `probed_now == false` (the cache-hit path
    /// already had a frame from the original probe run).
    pub frame_payload: Option<DetectCompletePayload>,
}

/// Orchestrator. Pure-fn over the cache + inputs + clock; the
/// caller spawns this on a tokio task when probes are live.
pub fn run_detect_step(
    neoth_home: &Path,
    now_unix: u64,
    inputs: &DetectStepInputs,
) -> std::io::Result<DetectStepOutcome> {
    if let Some(cached) = load_cache(neoth_home, now_unix) {
        return Ok(DetectStepOutcome {
            report: cached,
            probed_now: false,
            frame_payload: None,
        });
    }

    let report = assemble_report(
        now_unix,
        inputs.docker_version.clone(),
        inputs.docker_compose_version.clone(),
        inputs.docker_compose_legacy_version.clone(),
        inputs.npm_version.clone(),
        inputs.node_version.clone(),
        inputs.git_version.clone(),
        inputs.ffmpeg_version.clone(),
        inputs.gpu.clone(),
        inputs.disk_free_bytes,
    );
    save_cache(neoth_home, &report)?;
    let payload = DetectCompletePayload::from_report(&report);
    Ok(DetectStepOutcome {
        report,
        probed_now: true,
        frame_payload: Some(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::detect::DETECT_CACHE_TTL_SECS;
    use crate::installers::gpu::{GpuKind, GpuReport};

    fn sample_inputs() -> DetectStepInputs {
        DetectStepInputs {
            docker_version: Some("25.0.0".into()),
            docker_compose_version: Some("v2.24".into()),
            docker_compose_legacy_version: None,
            npm_version: Some("10.2".into()),
            node_version: Some("v20.10".into()),
            git_version: Some("2.42".into()),
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
    fn first_run_probes_and_writes_cache_and_returns_payload() {
        let home = tempfile::tempdir().unwrap();
        let outcome = run_detect_step(home.path(), 1_700_000_000, &sample_inputs()).unwrap();
        assert!(outcome.probed_now);
        assert!(outcome.frame_payload.is_some());
        let payload = outcome.frame_payload.unwrap();
        assert_eq!(payload.probed_at_unix, 1_700_000_000);
        assert_eq!(payload.docker_version.as_deref(), Some("25.0.0"));
        assert_eq!(payload.gpu_kind.as_deref(), Some("cuda"));
        // Cache file now exists on disk.
        assert!(home.path().join("detect_cache.json").exists());
    }

    #[test]
    fn second_run_within_ttl_short_circuits_no_payload() {
        let home = tempfile::tempdir().unwrap();
        let first = run_detect_step(home.path(), 1_700_000_000, &sample_inputs()).unwrap();
        assert!(first.probed_now);

        // Run again 5 min later → cache hit.
        let second = run_detect_step(home.path(), 1_700_000_300, &DetectStepInputs::default())
            .unwrap();
        assert!(!second.probed_now);
        assert!(
            second.frame_payload.is_none(),
            "cache hit must not emit a duplicate 0xD5 frame",
        );
        // Returned report is the cached one — docker version preserved
        // even though the second run's inputs left it None.
        assert_eq!(second.report.docker_version.as_deref(), Some("25.0.0"));
    }

    #[test]
    fn run_past_ttl_re_probes_and_emits_new_payload() {
        let home = tempfile::tempdir().unwrap();
        let first = run_detect_step(home.path(), 1_000_000_000, &sample_inputs()).unwrap();
        assert!(first.probed_now);

        // Now is past TTL.
        let mut inputs2 = sample_inputs();
        inputs2.docker_version = Some("26.0.0".into()); // operator upgraded docker
        let second =
            run_detect_step(home.path(), 1_000_000_000 + DETECT_CACHE_TTL_SECS + 1, &inputs2)
                .unwrap();
        assert!(second.probed_now);
        let payload = second.frame_payload.unwrap();
        assert_eq!(payload.docker_version.as_deref(), Some("26.0.0"));
        assert_eq!(payload.probed_at_unix, 1_000_000_000 + DETECT_CACHE_TTL_SECS + 1);
    }

    #[test]
    fn default_inputs_with_no_gpu_emit_payload_with_gpu_kind_none() {
        let home = tempfile::tempdir().unwrap();
        let outcome = run_detect_step(home.path(), 100, &DetectStepInputs::default()).unwrap();
        assert!(outcome.probed_now);
        let payload = outcome.frame_payload.unwrap();
        assert!(payload.gpu_kind.is_none());
        assert!(payload.docker_version.is_none());
    }

    #[test]
    fn payload_round_trips_through_report() {
        let home = tempfile::tempdir().unwrap();
        let outcome = run_detect_step(home.path(), 42, &sample_inputs()).unwrap();
        let payload = outcome.frame_payload.unwrap();
        // payload is what the WAL writer serialises; the
        // DetectReport on disk + the payload over the wire MUST
        // describe the same system.
        assert_eq!(payload.probed_at_unix, outcome.report.probed_at_unix);
        assert_eq!(payload.docker_version, outcome.report.docker_version);
    }

    #[test]
    fn cached_report_returned_when_hit() {
        let home = tempfile::tempdir().unwrap();
        run_detect_step(home.path(), 100, &sample_inputs()).unwrap();
        let outcome2 = run_detect_step(home.path(), 200, &DetectStepInputs::default()).unwrap();
        // The returned report has all the first run's data even
        // though the second call passed empty inputs.
        assert_eq!(outcome2.report.docker_version.as_deref(), Some("25.0.0"));
        assert_eq!(outcome2.report.npm_version.as_deref(), Some("10.2"));
        assert!(outcome2.report.gpu.is_some());
    }

    #[test]
    fn missing_home_dir_is_created_on_first_run() {
        // Use a path that doesn't exist yet — save_cache creates
        // parents.
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("fresh-neoth-home");
        let outcome = run_detect_step(&home, 100, &sample_inputs()).unwrap();
        assert!(outcome.probed_now);
        assert!(home.join("detect_cache.json").exists());
    }

    #[test]
    fn outcome_struct_equality_works_for_diffing() {
        // Wizard UIs may diff outcomes across re-runs.
        let home1 = tempfile::tempdir().unwrap();
        let home2 = tempfile::tempdir().unwrap();
        let o1 = run_detect_step(home1.path(), 100, &sample_inputs()).unwrap();
        let o2 = run_detect_step(home2.path(), 100, &sample_inputs()).unwrap();
        assert_eq!(o1.report, o2.report);
    }
}
