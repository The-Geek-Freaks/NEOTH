//! GOLD-FEAT-06 — local resource-snapshot cron.
//!
//! Samples this node's CPU, RAM, and VRAM on a configurable interval (default
//! 30 s), then writes an `EXTENDED/LocalSnapshot` WAL frame whose payload is
//! the JSON-serialized [`crate::cluster::swarm::NodeResourceSnapshot`].
//!
//! `neoth cluster swarm` reads these local frames plus peer
//! `EXTENDED/SwarmResourceSnapshot` frames to build the dashboard view. The
//! Hyperswarm heartbeat sends authenticated peer snapshots, and the receive
//! path persists them locally. The subtype-aware WAL ACL keeps
//! `LocalSnapshot` frames local while allowing `SwarmResourceSnapshot` frames.

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cluster::swarm::NodeResourceSnapshot;
use crate::config::SwarmConfig;
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::types::EventFlags;
use crate::wal::writer::WalWriterHandle;

// ── Public spawn API ─────────────────────────────────────────────────────────

/// Spawn the local resource-snapshot cron.
///
/// Returns `None` when `config.enabled = false` (no task created).
///
/// The cron samples CPU/RAM/VRAM once per `config.interval_secs` and emits an
/// `EXTENDED/LocalSnapshot` (event_type=0x00, event_subtype=0x04) WAL frame
/// whose payload is the JSON-serialized snapshot. The emitted frames are
/// consumed by `neoth cluster swarm`.
///
/// # Wiring
/// Managed by the daemon cron fleet as `CronKey::ResourceSnapshot`. Reloading
/// a changed `swarm.interval_secs` stops the old sampler and starts one task
/// with the new interval; `swarm.enabled = false` removes it from the fleet.
pub fn spawn_resource_snapshot_cron(
    config: SwarmConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        info!("resource_snapshot cron disabled (swarm.enabled = false)");
        return None;
    }

    let node_id = resolve_node_id();
    info!(
        interval_secs = config.interval_secs,
        node_id = %node_id,
        "resource_snapshot cron spawned (GOLD-FEAT-06)",
    );

    Some(tokio::spawn(async move {
        // Keep sysinfo System alive across ticks: the CPU-usage reading is a
        // differential between two consecutive refresh calls. Keeping `sys`
        // alive means the Nth tick has an N-1 → N delta, giving an accurate
        // reading after the first interval.
        let mut sys = new_system();

        let mut ticker = tokio::time::interval(config.interval_duration());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            interval_secs = config.interval_secs,
            "resource_snapshot cron online (GOLD-FEAT-06)",
        );

        loop {
            ticker.tick().await;

            let snap = sample_snapshot(&node_id, &mut sys);
            let payload = match serde_json::to_vec(&snap) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "resource_snapshot: failed to serialize snapshot; skipping tick");
                    continue;
                }
            };

            let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
                .event_subtype(ExtendedSubtype::LocalSnapshot as u8)
                .flags(EventFlags::empty())
                .build();

            if let Err(e) = writer.append(header, payload).await {
                warn!(error = %e, "resource_snapshot: WAL append failed");
            }
        }
    }))
}

// ── Internal helpers (pub(crate) so cluster/hyperswarm can call them for the
// ── gossip-piggyback without a separate sysinfo sampling path) ───────────────

/// Create a `sysinfo::System` pre-configured for CPU + memory polling.
///
/// Callers keep the returned value alive across ticks so that
/// [`sample_snapshot`] can compute a differential CPU reading.
pub(crate) fn new_system() -> sysinfo::System {
    use sysinfo::System;
    System::new()
}

/// Sample CPU%, RAM, and VRAM for this node.
///
/// `sys` is kept alive by the caller across ticks to give accurate CPU
/// differential readings (first tick reads ~0% — subsequent ticks give the
/// correct average over the interval).
pub(crate) fn sample_snapshot(node_id: &str, sys: &mut sysinfo::System) -> NodeResourceSnapshot {
    sys.refresh_cpu_all();
    sys.refresh_memory();

    // Average CPU across all logical cores. In sysinfo 0.32, `cpu_usage()`
    // returns the % since the previous refresh — accurate only from tick 2+.
    let cpu_count = sys.cpus().len().max(1);
    let cpu_total: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum();
    let cpu_pct = cpu_total / cpu_count as f32;

    // sysinfo 0.32 returns memory in bytes.
    let ram_used_mb = sys.used_memory() / 1_048_576;
    let ram_total_mb = sys.total_memory() / 1_048_576;

    let vram = probe_vram();
    let (vram_used_mb, vram_total_mb) = match vram {
        Some(v) => (Some(v.used_mib as u64), Some(v.total_mib as u64)),
        None => (None, None),
    };

    let hostname = resolve_node_id();
    NodeResourceSnapshot::new(
        node_id.to_string(),
        hostname,
        cpu_pct,
        ram_used_mb,
        ram_total_mb,
        vram_used_mb,
        vram_total_mb,
        crate::time::now_unix_i64(),
    )
}

/// Vendor-agnostic VRAM probe: NVIDIA (`nvidia-smi`) then AMD (`rocm-smi`).
///
/// Returns `None` on any failure — binary absent, non-zero exit, parse error,
/// or CPU-only host. Re-uses the public pure-function parsers from
/// [`crate::daemon::resource_watch`] to stay consistent with the existing
/// VRAM-reading infrastructure without depending on private helpers in
/// the dirty `daemon/hardware.rs` or `daemon/resource_watch.rs` internals.
fn probe_vram() -> Option<crate::daemon::resource_watch::VramReading> {
    // ── NVIDIA ───────────────────────────────────────────────────────────────
    if let Ok(out) = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().next() {
                if let Some(r) = crate::daemon::resource_watch::parse_vram_used_total(line) {
                    return Some(r);
                }
            }
        }
    }

    // ── AMD ──────────────────────────────────────────────────────────────────
    if let Ok(out) = std::process::Command::new("rocm-smi")
        .args(["--showmeminfo", "vram", "--csv"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            return crate::daemon::resource_watch::parse_amd_vram_csv(&text);
        }
    }

    None
}

/// Resolve the node identifier for this host.
///
/// Checked in order: `HOSTNAME` env var, `COMPUTERNAME` env var (Windows),
/// then the literal string `"unknown"`.
pub(crate) fn resolve_node_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `sample_snapshot` must return non-zero RAM on any real machine.
    /// CPU% may be ~0 on the first call (differential not yet primed), but
    /// total RAM is always present and must exceed zero.
    #[test]
    fn sample_snapshot_returns_real_ram() {
        let mut sys = new_system();
        let snap = sample_snapshot("test-node", &mut sys);
        assert!(
            snap.ram_total_mb > 0,
            "ram_total_mb must be >0 on a physical host (got {})",
            snap.ram_total_mb
        );
        // used ≤ total invariant enforced by NodeResourceSnapshot::new.
        assert!(
            snap.ram_used_mb <= snap.ram_total_mb,
            "ram_used_mb ({}) must not exceed ram_total_mb ({})",
            snap.ram_used_mb,
            snap.ram_total_mb,
        );
    }

    /// Second tick of sample_snapshot gives a positive CPU% on a busy host.
    /// We warm the sysinfo differential and do a second refresh — on any active
    /// machine the aggregate CPU should be ≥ 0.0 (strictly: we just assert it is
    /// a valid finite f32 in [0, 100]).
    #[test]
    fn sample_snapshot_cpu_pct_valid_range() {
        let mut sys = new_system();
        let _warm = sample_snapshot("warm", &mut sys); // prime differential
        let snap = sample_snapshot("test-node", &mut sys);
        assert!(
            snap.cpu_pct >= 0.0 && snap.cpu_pct <= 100.0,
            "cpu_pct must be in [0, 100], got {}",
            snap.cpu_pct
        );
        assert!(snap.cpu_pct.is_finite(), "cpu_pct must be finite");
    }

    /// `resolve_node_id` returns a non-empty string on any real host.
    #[test]
    fn resolve_node_id_returns_nonempty() {
        let id = resolve_node_id();
        assert!(
            !id.is_empty(),
            "resolve_node_id must return a non-empty string"
        );
    }

    /// `new_system` must return a usable sysinfo::System (no panic).
    #[test]
    fn new_system_does_not_panic() {
        let mut sys = new_system();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        // If we get here without panicking, the system initialised correctly.
    }

    #[tokio::test]
    async fn disabled_config_does_not_spawn_task() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, writer_task) =
            crate::wal::writer::spawn(dir.path().join("000001.wal")).unwrap();
        let config = SwarmConfig {
            enabled: false,
            ..SwarmConfig::default()
        };

        assert!(spawn_resource_snapshot_cron(config, writer).is_none());
        writer_task.await.unwrap();
    }
}
