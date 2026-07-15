//! `/healthz` + `/metrics` snapshot — Phase 33c BS-1.
//!
//! Provides a self-described daemon-state snapshot that the operator (or
//! a monitoring stack, or just `curl` against the local socket) can pull
//! at any time. Pure read — never writes WAL, never mutates state.
//!
//! ## Transport
//!
//! v0.1 exposes the snapshot as a CLI subcommand (`neoth status`) and as
//! a string-rendered helper for the daemon's `/healthz` HTTP endpoint
//! when that ships. Both consume [`snapshot()`] under the hood.
//!
//! The HTTP server itself lives in `cli/serve.rs` (Phase 33c BS-1 follow-up
//! will add a tokio listener); this module is only the data + rendering.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::config::FreedomConfig;
use crate::memory::{groundtruth, store};
use crate::permissions::AutonomyLevel;

/// Counters + state collected for a single observability snapshot.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Snapshot {
    pub daemon_version: &'static str,
    pub operator_id: Option<String>,
    pub autonomy: String,
    pub provider_kind: Option<String>,
    pub channels: Vec<String>,
    pub wal_segments: usize,
    pub wal_bytes_total: u64,
    pub idx_episode_rows: i64,
    pub idx_consolidated_rows: i64,
    pub idx_longterm_rows: i64,
    pub idx_groundtruth_active: i64,
    /// Vectors persisted in `idx_embedding`. Field defaults to 0 on
    /// pre-v6 databases so the snapshot stays compatible across
    /// schema versions.
    #[serde(default)]
    pub idx_embedding_rows: i64,
    pub archive_session_count: usize,
    pub clock_floor_ns: u64,
    /// Rolling-window provider call stats (Q-3). `None` when no meter has
    /// been wired into the snapshot path yet (CLI status path runs
    /// without one; `neoth serve` injects the live daemon meter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_meter: Option<MeterStats>,
}

/// Flat serialisable view of `providers::meter::Snapshot`. We mirror the
/// fields here so the snapshot module owns its own JSON shape and stays
/// decoupled from the meter's internal types (which it doesn't strictly
/// need to re-export for downstream consumers).
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub struct MeterStats {
    pub sample_count: usize,
    pub input_tps: f64,
    pub output_tps: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
}

impl From<crate::providers::meter::Snapshot> for MeterStats {
    fn from(s: crate::providers::meter::Snapshot) -> Self {
        MeterStats {
            sample_count: s.sample_count,
            input_tps: s.input_tps,
            output_tps: s.output_tps,
            p50_latency_ms: s.p50_latency_ms,
            p95_latency_ms: s.p95_latency_ms,
        }
    }
}

impl Snapshot {
    /// Render as a one-screen status table for the CLI.
    pub fn render_table(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(s, "# NEOTH status (daemon v{})", self.daemon_version);
        let _ = writeln!(
            s,
            "  operator:        {}",
            self.operator_id.as_deref().unwrap_or("(unset)"),
        );
        let _ = writeln!(s, "  autonomy:        {}", self.autonomy);
        let _ = writeln!(
            s,
            "  provider:        {}",
            self.provider_kind.as_deref().unwrap_or("(unset)"),
        );
        let _ = writeln!(
            s,
            "  channels:        {}",
            if self.channels.is_empty() {
                "(none)".to_string()
            } else {
                self.channels.join(", ")
            },
        );
        let _ = writeln!(
            s,
            "  WAL:             {} segments / {} bytes",
            self.wal_segments, self.wal_bytes_total,
        );
        let _ = writeln!(
            s,
            "  memory tiers:    {} hot / {} warm / {} long-term",
            self.idx_episode_rows, self.idx_consolidated_rows, self.idx_longterm_rows,
        );
        let _ = writeln!(
            s,
            "  ground truth:    {} active",
            self.idx_groundtruth_active,
        );
        let _ = writeln!(s, "  embeddings:      {} vectors", self.idx_embedding_rows,);
        let _ = writeln!(
            s,
            "  archive:         {} session files",
            self.archive_session_count,
        );
        let _ = writeln!(s, "  clock floor:     {} ns", self.clock_floor_ns);
        if let Some(m) = self.provider_meter {
            let _ = writeln!(
                s,
                "  provider:        {} calls / {:.2} in_tps / {:.2} out_tps / p50 {:.0}ms / p95 {:.0}ms",
                m.sample_count, m.input_tps, m.output_tps, m.p50_latency_ms, m.p95_latency_ms,
            );
        }
        s
    }

    /// Render as JSON for `--output json` and the future `/healthz` body.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render as Prometheus-style line protocol for the future `/metrics`
    /// endpoint. Pure-text, no scrape-library dependency.
    pub fn render_prometheus(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push_str("# HELP neoth_wal_segments Total WAL segment files\n");
        s.push_str("# TYPE neoth_wal_segments gauge\n");
        s.push_str(&format!("neoth_wal_segments {}\n", self.wal_segments));
        s.push_str("# HELP neoth_wal_bytes_total Total bytes across all WAL segments\n");
        s.push_str("# TYPE neoth_wal_bytes_total gauge\n");
        s.push_str(&format!("neoth_wal_bytes_total {}\n", self.wal_bytes_total));
        s.push_str("# HELP neoth_idx_episode_rows idx_episode row count (hot tier)\n");
        s.push_str("# TYPE neoth_idx_episode_rows gauge\n");
        s.push_str(&format!(
            "neoth_idx_episode_rows {}\n",
            self.idx_episode_rows
        ));
        s.push_str("# HELP neoth_idx_consolidated_rows idx_consolidated row count (warm tier)\n");
        s.push_str("# TYPE neoth_idx_consolidated_rows gauge\n");
        s.push_str(&format!(
            "neoth_idx_consolidated_rows {}\n",
            self.idx_consolidated_rows,
        ));
        s.push_str("# HELP neoth_idx_longterm_rows idx_longterm row count (cold tier)\n");
        s.push_str("# TYPE neoth_idx_longterm_rows gauge\n");
        s.push_str(&format!(
            "neoth_idx_longterm_rows {}\n",
            self.idx_longterm_rows,
        ));
        s.push_str("# HELP neoth_groundtruth_active Active (non-revoked) ground-truth rows\n");
        s.push_str("# TYPE neoth_groundtruth_active gauge\n");
        s.push_str(&format!(
            "neoth_groundtruth_active {}\n",
            self.idx_groundtruth_active,
        ));
        s.push_str(
            "# HELP neoth_idx_embedding_rows Persisted CLIP / multimodal embedding vectors\n",
        );
        s.push_str("# TYPE neoth_idx_embedding_rows gauge\n");
        s.push_str(&format!(
            "neoth_idx_embedding_rows {}\n",
            self.idx_embedding_rows,
        ));
        if let Some(m) = self.provider_meter {
            s.push_str("# HELP neoth_provider_calls Provider calls in the rolling window\n");
            s.push_str("# TYPE neoth_provider_calls gauge\n");
            s.push_str(&format!("neoth_provider_calls {}\n", m.sample_count));
            s.push_str(
                "# HELP neoth_provider_input_tps Average input tokens per second (rolling)\n",
            );
            s.push_str("# TYPE neoth_provider_input_tps gauge\n");
            s.push_str(&format!("neoth_provider_input_tps {}\n", m.input_tps));
            s.push_str(
                "# HELP neoth_provider_output_tps Average output tokens per second (rolling)\n",
            );
            s.push_str("# TYPE neoth_provider_output_tps gauge\n");
            s.push_str(&format!("neoth_provider_output_tps {}\n", m.output_tps));
            s.push_str("# HELP neoth_provider_latency_p50_ms 50th percentile latency over the rolling window\n");
            s.push_str("# TYPE neoth_provider_latency_p50_ms gauge\n");
            s.push_str(&format!(
                "neoth_provider_latency_p50_ms {}\n",
                m.p50_latency_ms
            ));
            s.push_str("# HELP neoth_provider_latency_p95_ms 95th percentile latency over the rolling window\n");
            s.push_str("# TYPE neoth_provider_latency_p95_ms gauge\n");
            s.push_str(&format!(
                "neoth_provider_latency_p95_ms {}\n",
                m.p95_latency_ms
            ));
        }
        s
    }
}

/// Build a snapshot by reading the on-disk state. Tolerates missing files
/// (`views.db`, WAL segments, archive) — fresh installs return zeros, not
/// errors. Caller-supplied overrides let tests work without `~/.neoth/`.
pub fn snapshot(home: &Path, config: Option<&FreedomConfig>) -> Result<Snapshot> {
    let wal_dir = home.join("wal");
    let archive_dir = home.join("archive").join("sessions");
    let db_path = home.join("views.db");
    let clock_path = home.join("clock.floor");

    let (wal_segments, wal_bytes_total) = count_wal(&wal_dir);
    let archive_session_count = count_archive_sessions(&archive_dir);
    let clock_floor_ns = read_clock_floor(&clock_path);
    let (
        idx_episode_rows,
        idx_consolidated_rows,
        idx_longterm_rows,
        idx_groundtruth_active,
        idx_embedding_rows,
    ) = count_db_rows(&db_path).unwrap_or((0, 0, 0, 0, 0));

    let (operator_id, autonomy, provider_kind, channels) = match config {
        Some(cfg) => (
            cfg.operator_id.clone(),
            cfg.autonomy.as_str().to_string(),
            cfg.provider_kind.map(|p| format!("{p:?}").to_lowercase()),
            channels_from_config(cfg),
        ),
        None => (
            None,
            AutonomyLevel::default().as_str().to_string(),
            None,
            Vec::new(),
        ),
    };

    Ok(Snapshot {
        daemon_version: env!("CARGO_PKG_VERSION"),
        operator_id,
        autonomy,
        provider_kind,
        channels,
        wal_segments,
        wal_bytes_total,
        idx_episode_rows,
        idx_consolidated_rows,
        idx_longterm_rows,
        idx_groundtruth_active,
        idx_embedding_rows,
        archive_session_count,
        clock_floor_ns,
        provider_meter: None,
    })
}

/// Same as `snapshot` but enriches the result with a live meter's current
/// stats. Used by the daemon's `/healthz` handler where the meter is alive.
pub fn snapshot_with_meter(
    home: &Path,
    config: Option<&FreedomConfig>,
    meter: &crate::providers::meter::Meter,
) -> Result<Snapshot> {
    let mut s = snapshot(home, config)?;
    s.provider_meter = Some(meter.snapshot().into());
    Ok(s)
}

fn count_wal(wal_dir: &Path) -> (usize, u64) {
    let Ok(rd) = std::fs::read_dir(wal_dir) else {
        return (0, 0);
    };
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        count += 1;
        if let Ok(meta) = entry.metadata() {
            bytes += meta.len();
        }
    }
    (count, bytes)
}

fn count_archive_sessions(dir: &Path) -> usize {
    fn walk_count(dir: &Path) -> usize {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut count = 0usize;
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += walk_count(&path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("md") {
                count += 1;
            }
        }
        count
    }
    walk_count(dir)
}

fn read_clock_floor(path: &Path) -> u64 {
    let Ok(body) = std::fs::read_to_string(path) else {
        return 0;
    };
    body.trim().parse::<u64>().unwrap_or(0)
}

fn count_db_rows(db: &Path) -> Result<(i64, i64, i64, i64, i64)> {
    if !db.exists() {
        return Ok((0, 0, 0, 0, 0));
    }
    let conn = store::open(db)?;
    let episode: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap_or(0);
    let consolidated: i64 = conn
        .query_row("SELECT count(*) FROM idx_consolidated", [], |r| r.get(0))
        .unwrap_or(0);
    let longterm: i64 = conn
        .query_row("SELECT count(*) FROM idx_longterm", [], |r| r.get(0))
        .unwrap_or(0);
    let gt = groundtruth::count_active(&conn).unwrap_or(0);
    // Embedding count is best-effort: pre-v6 databases lack the table
    // and we'd rather report zero than fail the snapshot.
    let embedding: i64 = conn
        .query_row("SELECT count(*) FROM idx_embedding", [], |r| r.get(0))
        .unwrap_or(0);
    Ok((episode, consolidated, longterm, gt, embedding))
}

fn channels_from_config(cfg: &FreedomConfig) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.telegram_token.is_some() {
        out.push("telegram".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_home_returns_zeros() {
        let dir = tempdir().unwrap();
        let snap = snapshot(dir.path(), None).unwrap();
        assert_eq!(snap.wal_segments, 0);
        assert_eq!(snap.wal_bytes_total, 0);
        assert_eq!(snap.idx_episode_rows, 0);
        assert_eq!(snap.idx_embedding_rows, 0);
        assert_eq!(snap.archive_session_count, 0);
        assert_eq!(snap.autonomy, "standard");
    }

    #[test]
    fn counts_embedding_rows_when_table_present() {
        use crate::memory::embeddings;
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        // Open via the canonical store path so the v6 schema lands.
        let conn = store::open(&db_path).unwrap();
        let unit_vec: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
        embeddings::upsert(&conn, "image", "a.png", "test", &unit_vec).unwrap();
        embeddings::upsert(&conn, "image", "b.png", "test", &unit_vec).unwrap();
        drop(conn);
        let snap = snapshot(dir.path(), None).unwrap();
        assert_eq!(snap.idx_embedding_rows, 2);
    }

    #[test]
    fn prometheus_output_includes_embedding_gauge() {
        let mut snap = snapshot(tempdir().unwrap().path(), None).unwrap();
        snap.idx_embedding_rows = 7;
        let body = snap.render_prometheus();
        assert!(body.contains("neoth_idx_embedding_rows 7"));
        assert!(body.contains("# TYPE neoth_idx_embedding_rows gauge"));
    }

    #[test]
    fn counts_wal_segments_and_bytes() {
        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::write(wal_dir.join("000001.wal"), [0u8; 100]).unwrap();
        std::fs::write(wal_dir.join("000002.wal"), [0u8; 200]).unwrap();
        std::fs::write(wal_dir.join("ignore.txt"), [0u8; 50]).unwrap();
        let snap = snapshot(dir.path(), None).unwrap();
        assert_eq!(snap.wal_segments, 2);
        assert_eq!(snap.wal_bytes_total, 300);
    }

    #[test]
    fn counts_archive_session_md_files() {
        let dir = tempdir().unwrap();
        let day = dir
            .path()
            .join("archive")
            .join("sessions")
            .join("2026-05-14");
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("a.md"), "x").unwrap();
        std::fs::write(day.join("b.md"), "x").unwrap();
        std::fs::write(day.join("notes.txt"), "x").unwrap();
        let snap = snapshot(dir.path(), None).unwrap();
        assert_eq!(snap.archive_session_count, 2);
    }

    #[test]
    fn reads_clock_floor() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("clock.floor"), "1700000000\n").unwrap();
        let snap = snapshot(dir.path(), None).unwrap();
        assert_eq!(snap.clock_floor_ns, 1_700_000_000);
    }

    #[test]
    fn render_table_includes_every_field() {
        let snap = Snapshot {
            daemon_version: "0.1.0",
            operator_id: Some("sam".into()),
            autonomy: "standard".into(),
            provider_kind: Some("claude_cli".into()),
            channels: vec!["telegram".into()],
            wal_segments: 3,
            wal_bytes_total: 42_000,
            idx_episode_rows: 1,
            idx_consolidated_rows: 2,
            idx_longterm_rows: 3,
            idx_groundtruth_active: 4,
            idx_embedding_rows: 0,
            archive_session_count: 5,
            clock_floor_ns: 1_700_000_000,
            provider_meter: None,
        };
        let s = snap.render_table();
        assert!(s.contains("sam"));
        assert!(s.contains("standard"));
        assert!(s.contains("3 segments"));
        assert!(s.contains("telegram"));
        assert!(s.contains("1 hot / 2 warm / 3 long-term"));
        assert!(s.contains("4 active"));
    }

    #[test]
    fn render_prometheus_uses_neoth_prefix() {
        let snap = Snapshot {
            daemon_version: "0.1.0",
            operator_id: None,
            autonomy: "strict".into(),
            provider_kind: None,
            channels: vec![],
            wal_segments: 7,
            wal_bytes_total: 999,
            idx_episode_rows: 11,
            idx_consolidated_rows: 22,
            idx_longterm_rows: 33,
            idx_groundtruth_active: 44,
            idx_embedding_rows: 55,
            archive_session_count: 0,
            clock_floor_ns: 0,
            provider_meter: None,
        };
        let p = snap.render_prometheus();
        assert!(p.contains("neoth_wal_segments 7"));
        assert!(p.contains("neoth_wal_bytes_total 999"));
        assert!(p.contains("neoth_idx_episode_rows 11"));
        assert!(p.contains("neoth_groundtruth_active 44"));
        assert!(p.contains("# TYPE neoth_wal_segments gauge"));
    }

    #[test]
    fn render_json_is_valid_object() {
        let snap = Snapshot {
            daemon_version: "0.1.0",
            operator_id: None,
            autonomy: "standard".into(),
            provider_kind: None,
            channels: vec![],
            wal_segments: 0,
            wal_bytes_total: 0,
            idx_episode_rows: 0,
            idx_consolidated_rows: 0,
            idx_longterm_rows: 0,
            idx_groundtruth_active: 0,
            idx_embedding_rows: 0,
            archive_session_count: 0,
            clock_floor_ns: 0,
            provider_meter: None,
        };
        let j: serde_json::Value = serde_json::from_str(&snap.render_json().unwrap()).unwrap();
        assert_eq!(j["daemon_version"], "0.1.0");
        assert!(j.get("idx_episode_rows").is_some());
    }
}
