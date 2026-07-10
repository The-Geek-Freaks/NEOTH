//! GOLD-FEAT-06 — local resource-snapshot cron.
//!
//! Samples this node's CPU, RAM, and VRAM on a configurable interval (default
//! 30 s), then writes an `EXTENDED/LocalSnapshot` WAL frame whose payload is
//! the JSON-serialized [`crate::cluster::swarm::NodeResourceSnapshot`].
//!
//! `neoth cluster swarm` reads these frames (and peer `EXTENDED/SwarmResourceSnapshot`
//! frames if gossip replication is wired later) to build the dashboard view.
//!
//! # Gossip replication note (deferred — TODO DES-14)
//! `wal_sync::classify_event` branches on the top-level `event_type` byte only.
//! All `EVENT_TYPE_EXTENDED` (0x00) frames — regardless of subtype — are
//! treated identically by the ACL. Replicating only `SwarmResourceSnapshot`
//! (0x03) but not `LocalSnapshot` (0x04) requires a classify_event update
//! that keys on `(event_type, event_subtype)`. That change touches hot files
//! owned by a parallel session; leave gossip replication as a follow-up and
//! document the limitation here so the shippable core is the WAL emit +
//! `neoth cluster swarm` reading local frames.

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cluster::swarm::{NodeResourceSnapshot, SwarmConfig};
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
/// Called from `cli/serve.rs` immediately after the cluster transport block:
/// ```rust,ignore
/// #[cfg(feature = "cluster")]
/// let _ = crate::daemon::resource_snapshot_cron::spawn_resource_snapshot_cron(
///     crate::cluster::swarm::SwarmConfig::default(),
///     writer.clone(),
/// );
/// ```
/// TODO(FEAT-06): pass `config.swarm` (a `SwarmConfig` field on `FreedomConfig`)
/// once `config/mod.rs` is unfrozen.
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

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Create a `sysinfo::System` pre-configured for CPU + memory polling.
fn new_system() -> sysinfo::System {
    use sysinfo::System;
    System::new()
}

/// Sample CPU%, RAM, and VRAM for this node.
///
/// `sys` is kept alive by the caller across ticks to give accurate CPU
/// differential readings (first tick reads ~0% — subsequent ticks give the
/// correct average over the interval).
fn sample_snapshot(node_id: &str, sys: &mut sysinfo::System) -> NodeResourceSnapshot {
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
fn resolve_node_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
