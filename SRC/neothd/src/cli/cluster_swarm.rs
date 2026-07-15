//! GOLD-FEAT-06 — `neoth cluster swarm` — exo-style swarm resource dashboard.
//!
//! Reads `EXTENDED/LocalSnapshot` (type=0x00, subtype=0x04) and
//! `EXTENDED/SwarmResourceSnapshot` (type=0x00, subtype=0x03) WAL frames,
//! builds an in-memory [`SwarmTable`], prunes stale entries, and prints a
//! table or JSON summary of per-node CPU/RAM/VRAM utilisation.
//!
//! `--watch` enters a loop that clears the terminal and refreshes every 5 s
//! (exit with Ctrl-C).
//!
//! The command is wired through `cli::cluster::ClusterAction::Swarm`. Its
//! sampling interval and default stale threshold come from
//! `freedom.yaml::swarm`; `--stale-secs` is an explicit one-shot override.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::cluster::swarm::{NodeResourceSnapshot, SwarmTable};
use crate::config::{FreedomConfig, SwarmConfig};
use crate::wal::compress::decompress_frames;
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

// ── CLI args ──────────────────────────────────────────────────────────────────

/// Arguments for `neoth cluster swarm`.
#[derive(Args, Debug, Clone, Default)]
pub struct ClusterSwarmArgs {
    /// Continuously refresh the dashboard every 5 s. Exit with Ctrl-C.
    #[arg(long, short = 'w')]
    pub watch: bool,

    /// Drop nodes whose last snapshot is older than this many seconds.
    /// Defaults to `freedom.yaml::swarm.stale_after_secs` (300).
    /// Must be greater than zero; an explicit value overrides config.
    #[arg(long)]
    pub stale_secs: Option<i64>,

    /// Output format (table or json). Populated by the parent command.
    #[arg(skip)]
    pub output: OutputFormat,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run `neoth cluster swarm [--watch] [--output json|table]`.
pub async fn run_cluster_swarm(args: ClusterSwarmArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    let config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml swarm dashboard policy")?;
    let stale_secs = resolve_stale_secs(args.stale_secs, config.swarm.stale_after_secs)?;

    if args.watch {
        loop {
            // Clear terminal between refreshes.
            print!("\x1B[2J\x1B[H");
            print_swarm(&wal_dir, config.swarm, stale_secs, &args.output)?;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    } else {
        print_swarm(&wal_dir, config.swarm, stale_secs, &args.output)
    }
}

/// Resolve the effective stale threshold (seconds) for snapshot pruning.
///
/// CLI `--stale-secs` overrides `SwarmConfig::stale_after_secs`; both surfaces
/// reject zero/negative windows so pruning cannot invert or immediately erase
/// the dashboard.
pub(crate) fn resolve_stale_secs(cli_override: Option<i64>, configured: i64) -> Result<i64> {
    let stale_secs = cli_override.unwrap_or(configured);
    if stale_secs <= 0 {
        anyhow::bail!("swarm stale threshold must be greater than zero seconds");
    }
    Ok(stale_secs)
}

// ── Output ────────────────────────────────────────────────────────────────────

fn print_swarm(
    wal_dir: &Path,
    config: SwarmConfig,
    stale_secs: i64,
    output: &OutputFormat,
) -> Result<()> {
    let mut table = SwarmTable::new();

    // Only scan segments recent enough to still hold a non-stale snapshot. A
    // segment last modified before `now - stale_secs - margin` can only contain
    // frames that prune() would drop, so skipping it never hides a live node.
    // Bounds the `--watch` rescan to the active tail instead of re-reading the
    // entire WAL (O(total WAL size)) every 5 s.
    // ponytail: mtime filter, not a per-segment byte-offset cursor — good
    // enough while the active window is small; add a read cursor if it grows.
    let cutoff = crate::time::now_unix_i64()
        .saturating_sub(stale_secs.saturating_add(SWARM_MTIME_MARGIN_SECS));

    // Scan candidate WAL segments (tolerant — a corrupt segment is skipped).
    for seg_path in sorted_segments(wal_dir) {
        if !segment_is_live(segment_mtime_unix(&seg_path), cutoff) {
            continue;
        }
        if let Err(e) = scan_segment_into_table(&seg_path, &mut table) {
            tracing::warn!(
                error = %e,
                segment = %seg_path.display(),
                "cluster swarm: skipped unreadable segment",
            );
        }
    }

    table.prune(stale_secs);
    let rows = table.rows();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json_rows: Vec<serde_json::Value> =
                rows.iter().map(|r| snapshot_to_json(r)).collect();
            println!(
                "{}",
                serde_json::json!({
                    "sampling": swarm_policy_json(config, stale_secs),
                    "nodes": json_rows,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "# sampling_enabled={}, interval_secs={}, configured_stale_secs={}, effective_stale_secs={}",
                config.enabled, config.interval_secs, config.stale_after_secs, stale_secs,
            );
            if rows.is_empty() {
                println!(
                    "# no swarm snapshot frames found in WAL\n\
                     # start the daemon with `neoth serve` to emit LocalSnapshot frames\n\
                     # (EXTENDED/LocalSnapshot, event_type=0x00, subtype=0x04)"
                );
                return Ok(());
            }
            let now = crate::time::now_unix_i64();
            println!(
                "{:<22}  {:<22}  {:>6}  {:>14}  {:>14}  {:>14}  {:>14}  {:>7}",
                "node_id",
                "hostname",
                "cpu%",
                "ram_used(MiB)",
                "ram_total(MiB)",
                "vram_used(MiB)",
                "vram_total(MiB)",
                "age_s",
            );
            println!("{}", "-".repeat(115));
            for r in &rows {
                let vram_u = r
                    .vram_used_mb
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let vram_t = r
                    .vram_total_mb
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let age_s = (now - r.ts_unix).max(0);
                println!(
                    "{:<22}  {:<22}  {:>5.1}  {:>14}  {:>14}  {:>14}  {:>14}  {:>7}",
                    trunc(&r.node_id, 22),
                    trunc(&r.hostname, 22),
                    r.cpu_pct,
                    r.ram_used_mb,
                    r.ram_total_mb,
                    vram_u,
                    vram_t,
                    age_s,
                );
            }
            println!("{}", "-".repeat(115));
            println!("# {} node(s)", rows.len());
        }
    }
    Ok(())
}

/// Serialize the effective dashboard policy so JSON output exposes the same
/// config state as the human-readable status line.
fn swarm_policy_json(config: SwarmConfig, stale_secs: i64) -> serde_json::Value {
    serde_json::json!({
        "enabled": config.enabled,
        "interval_secs": config.interval_secs,
        "configured_stale_after_secs": config.stale_after_secs,
        "effective_stale_after_secs": stale_secs,
    })
}

/// Serialize a snapshot to a JSON value with all required fields.
///
/// `age_s` is a convenience field: `now_unix_i64() - ts_unix`, clamped ≥ 0.
/// It lets consumers display "how stale is this reading?" without computing
/// the current wall-clock time themselves.
pub fn snapshot_to_json(r: &NodeResourceSnapshot) -> serde_json::Value {
    let age_s = (crate::time::now_unix_i64() - r.ts_unix).max(0);
    serde_json::json!({
        "node_id":      r.node_id,
        "hostname":     r.hostname,
        "cpu_pct":      r.cpu_pct,
        "ram_used_mb":  r.ram_used_mb,
        "ram_total_mb": r.ram_total_mb,
        "vram_used_mb": r.vram_used_mb,
        "vram_total_mb":r.vram_total_mb,
        "ts_unix":      r.ts_unix,
        "age_s":        age_s,
    })
}

// ── WAL scanning ─────────────────────────────────────────────────────────────

/// Scan one WAL segment and upsert every `EXTENDED/LocalSnapshot` (0x04) and
/// `EXTENDED/SwarmResourceSnapshot` (0x03) frame into `table`.
///
/// Mirrors the tolerant scanning pattern in `cli/wal.rs::read_segment_frames`:
/// a torn frame (failed `decode_frame`) stops processing of the current segment
/// cleanly; the segment is not an error unless the segment header itself is
/// unreadable.
fn scan_segment_into_table(path: &Path, table: &mut SwarmTable) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;

    let hdr = match parse_segment_header(&bytes) {
        Ok(h) => h,
        // Corrupt / incompatible segment header → skip silently (return Ok).
        Err(e) => {
            tracing::debug!(
                error = %e,
                segment = %path.display(),
                "cluster swarm: segment header unreadable, skipping",
            );
            return Ok(());
        }
    };

    let header_len = hdr.header_len();
    if bytes.len() <= header_len {
        return Ok(()); // segment has no frames
    }

    let body = &bytes[header_len..];
    let decompressed: Vec<u8>;
    let frames: &[u8] = if hdr.is_compressed() {
        decompressed =
            decompress_frames(body).with_context(|| format!("decompress {}", path.display()))?;
        &decompressed
    } else {
        body
    };

    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break, // torn tail — stop this segment cleanly
        };

        let total = dec.header.total_len as usize;

        // Only EXTENDED frames (event_type=0x00) carry swarm snapshots.
        if dec.header.event_type == EVENT_TYPE_EXTENDED {
            let sub = dec.header.event_subtype;
            if sub == ExtendedSubtype::LocalSnapshot as u8
                || sub == ExtendedSubtype::SwarmResourceSnapshot as u8
            {
                match serde_json::from_slice::<NodeResourceSnapshot>(dec.payload) {
                    Ok(snap) => table.upsert(snap),
                    Err(e) => tracing::debug!(
                        error = %e,
                        subtype = sub,
                        "cluster swarm: failed to deserialize snapshot payload",
                    ),
                }
            }
        }

        if total == 0 {
            break; // guard against a zero total_len causing an infinite loop
        }
        cursor += total;
    }
    Ok(())
}

/// Return sorted `*.wal` paths under `wal_dir`. Empty when the dir is missing.
/// Clock-skew margin (seconds) added to `stale_secs` when deciding whether a
/// segment's mtime is too old to hold a live frame. File mtime and the frame's
/// embedded `ts_unix` can drift slightly; the margin keeps the filter from
/// dropping a still-live segment on a borderline mtime.
const SWARM_MTIME_MARGIN_SECS: i64 = 60;

/// File mtime as a Unix timestamp (seconds), or `None` if unreadable.
fn segment_mtime_unix(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(dur.as_secs() as i64)
}

/// Whether a segment with the given mtime could still hold a non-stale frame.
/// `None` (mtime unreadable) is treated as live — never skip on uncertainty.
fn segment_is_live(mtime_unix: Option<i64>, cutoff: i64) -> bool {
    match mtime_unix {
        Some(m) => m >= cutoff,
        None => true,
    }
}

fn sorted_segments(wal_dir: &Path) -> Vec<PathBuf> {
    let mut segs: Vec<PathBuf> = match std::fs::read_dir(wal_dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect(),
        Err(_) => Vec::new(),
    };
    segs.sort();
    segs
}

/// Truncate a string to at most `max` CHARACTERS. Byte-slicing (`&s[..max]`)
/// panics when `max` lands inside a multibyte codepoint, and hostnames can
/// carry Unicode — so truncate on char boundaries.
fn trunc(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::swarm::{NodeResourceSnapshot, SwarmTable};

    // ── resolve_stale_secs ────────────────────────────────────────────────

    /// No CLI arg → the loaded `SwarmConfig::stale_after_secs` wins.
    #[test]
    fn resolve_stale_secs_defaults_to_swarm_config_field() {
        assert_eq!(resolve_stale_secs(None, 777).unwrap(), 777);
    }

    /// Explicit CLI arg must override the config default.
    #[test]
    fn resolve_stale_secs_cli_override_wins() {
        assert_eq!(
            resolve_stale_secs(Some(60), 300).unwrap(),
            60,
            "explicit CLI arg must override SwarmConfig default"
        );
        assert!(resolve_stale_secs(Some(0), 300).is_err());
        assert!(resolve_stale_secs(Some(-1), 300).is_err());
        assert!(resolve_stale_secs(None, 0).is_err());
    }

    #[test]
    fn swarm_status_reports_loaded_and_effective_policy() {
        let config = SwarmConfig {
            enabled: false,
            interval_secs: 45,
            stale_after_secs: 900,
        };
        let policy = swarm_policy_json(config, 60);

        assert_eq!(policy["enabled"].as_bool(), Some(false));
        assert_eq!(policy["interval_secs"].as_u64(), Some(45));
        assert_eq!(policy["configured_stale_after_secs"].as_i64(), Some(900));
        assert_eq!(policy["effective_stale_after_secs"].as_i64(), Some(60));
    }

    fn make_snap(node_id: &str, ts_unix: i64) -> NodeResourceSnapshot {
        NodeResourceSnapshot::new(
            node_id.to_string(),
            "testhost".to_string(),
            42.0,
            4096,
            16384,
            Some(1024),
            Some(8192),
            ts_unix,
        )
    }

    // ── snapshot_to_json field shape ─────────────────────────────────────

    #[test]
    fn snapshot_json_has_all_required_fields() {
        let snap = make_snap("node-1", 1_700_000_000);
        let j = snapshot_to_json(&snap);

        // All fields the task spec requires must be present.
        assert!(j.get("node_id").is_some(), "node_id missing");
        assert!(j.get("hostname").is_some(), "hostname missing");
        assert!(j.get("cpu_pct").is_some(), "cpu_pct missing");
        assert!(j.get("ram_used_mb").is_some(), "ram_used_mb missing");
        assert!(j.get("ram_total_mb").is_some(), "ram_total_mb missing");
        assert!(j.get("vram_used_mb").is_some(), "vram_used_mb missing");
        assert!(j.get("vram_total_mb").is_some(), "vram_total_mb missing");
        assert!(j.get("ts_unix").is_some(), "ts_unix missing");

        assert_eq!(j["node_id"].as_str(), Some("node-1"));
        assert_eq!(j["hostname"].as_str(), Some("testhost"));
        assert!((j["cpu_pct"].as_f64().unwrap() - 42.0).abs() < 0.01);
        assert_eq!(j["ram_used_mb"].as_u64(), Some(4096));
        assert_eq!(j["ram_total_mb"].as_u64(), Some(16384));
        assert_eq!(j["vram_used_mb"].as_u64(), Some(1024));
        assert_eq!(j["vram_total_mb"].as_u64(), Some(8192));
        assert_eq!(j["ts_unix"].as_i64(), Some(1_700_000_000));
    }

    #[test]
    fn snapshot_json_null_vram_when_none() {
        let snap = NodeResourceSnapshot::new(
            "cpu-only".into(),
            "box".into(),
            10.0,
            2048,
            8192,
            None,
            None,
            0,
        );
        let j = snapshot_to_json(&snap);
        assert!(j["vram_used_mb"].is_null(), "expected null vram_used_mb");
        assert!(j["vram_total_mb"].is_null(), "expected null vram_total_mb");
    }

    // ── scan_segment_into_table with a hand-built WAL segment ────────────

    #[test]
    fn scan_segment_ignores_non_extended_frames() {
        use crate::wal::builder::HeaderBuilder;
        use crate::wal::events::EVENT_TYPE_EXTENDED;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::SegmentHeader;
        use crate::wal::types::EventFlags;

        let dir = tempfile::tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");

        // Build a minimal segment with one LocalSnapshot frame.
        let snap = make_snap("scan-node", 9999);
        let payload = serde_json::to_vec(&snap).unwrap();
        let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::LocalSnapshot as u8)
            .flags(EventFlags::empty())
            .build();

        let seg_hdr = SegmentHeader::new(0, 1, 0, 0, [0u8; 16]);
        let mut bytes: Vec<u8> = seg_hdr.to_le_bytes().to_vec();
        bytes.extend_from_slice(&encode_frame(&header, &payload));
        std::fs::write(&seg_path, &bytes).unwrap();

        let mut table = SwarmTable::new();
        scan_segment_into_table(&seg_path, &mut table).unwrap();

        assert_eq!(table.len(), 1, "exactly one snapshot should be extracted");
        let rows = table.rows();
        assert_eq!(rows[0].node_id, "scan-node");
        assert_eq!(rows[0].ts_unix, 9999);
    }

    // ── stale-entry pruning via the full scan-then-prune path ────────────

    #[test]
    fn stale_entries_pruned_after_scan() {
        let mut table = SwarmTable::new();
        table.upsert(make_snap("old-node", 0)); // ancient: ts_unix = epoch
        table.upsert(make_snap("fresh-node", i64::MAX / 2)); // far-future: always fresh
        table.prune(1); // anything older than 1 s is stale
        assert_eq!(table.len(), 1);
        assert_eq!(table.rows()[0].node_id, "fresh-node");
    }

    // ── sorted_segments ──────────────────────────────────────────────────

    #[test]
    fn sorted_segments_empty_when_dir_missing() {
        let segs = sorted_segments(Path::new("/nonexistent/path/wal"));
        assert!(segs.is_empty());
    }

    #[test]
    fn segment_is_live_skips_old_keeps_recent_and_unknown() {
        let cutoff = 1000;
        assert!(!segment_is_live(Some(999), cutoff)); // older than cutoff → skip
        assert!(segment_is_live(Some(1000), cutoff)); // exactly cutoff → keep
        assert!(segment_is_live(Some(2000), cutoff)); // newer → keep
        assert!(segment_is_live(None, cutoff)); // unknown mtime → keep, never skip on uncertainty
    }

    #[test]
    fn segment_mtime_unix_reads_fresh_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("000001.wal");
        std::fs::write(&p, b"x").unwrap();
        let mt = segment_mtime_unix(&p).expect("fresh file has readable mtime");
        // Sanity: a just-written file's mtime is a plausible recent unix time.
        assert!(mt > 1_000_000_000, "mtime looks wrong: {mt}");
        assert!(segment_mtime_unix(Path::new("/nonexistent/x.wal")).is_none());
    }

    #[test]
    fn sorted_segments_filters_non_wal_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("000001.wal"), b"").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"").unwrap();
        let segs = sorted_segments(dir.path());
        assert_eq!(segs.len(), 1);
        assert!(segs[0].to_str().unwrap().ends_with(".wal"));
    }
}
