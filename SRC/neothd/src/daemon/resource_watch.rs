//! SL-03 (A2 #3 sub-item) — ResourcePressureWatcher daemon cron.
//!
//! Polls live GPU VRAM usage on a short interval and emits a
//! `0x47 RESOURCE_PRESSURE_ALERT` WAL frame when usage crosses the
//! operator's `freedom.yaml::resource_watch.vram_threshold_pct` (default
//! 90%), so `neoth wal show --type resource_pressure_alert` is a durable,
//! grep-able record of when the box ran hot. **Advisory only** — it never
//! kills a job; it surfaces the pressure so the operator (or a future
//! scheduler) can react.
//!
//! Mirrors [`super::drift_alert_cron`]: an injectable-reading,
//! unit-testable [`run_resource_watch_tick`] + a
//! [`spawn_resource_watch_loop`] that returns `None` when disabled
//! (default OFF — no idle tokio task for opt-out operators).
//!
//! The live reading is best-effort + vendor-agnostic: [`read_gpu_vram`]
//! tries `nvidia-smi` (NVIDIA) then `rocm-smi` (AMD); on a host with
//! neither tool (no-GPU / Intel-integrated / CPU-only) it returns `None`
//! and the tick is a clean no-op (the watcher is useful on GPU boxes,
//! invisible elsewhere). Both vendor PARSERS + the threshold evaluator
//! are pure + tested; the subprocesses themselves are not.

use crate::config::ResourceWatchConfig;
use crate::wal::writer::WalWriterHandle;

/// A live VRAM reading — used + total in MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct VramReading {
    pub used_mib: u32,
    pub total_mib: u32,
}

impl VramReading {
    /// Percent of VRAM in use. `0.0` when total is 0 (degenerate / no GPU).
    pub fn pressure_pct(&self) -> f64 {
        if self.total_mib == 0 {
            return 0.0;
        }
        (self.used_mib as f64 / self.total_mib as f64) * 100.0
    }
}

/// A threshold breach: the reading, the computed pct, and the threshold
/// it crossed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PressureAlert {
    pub used_mib: u32,
    pub total_mib: u32,
    pub pct: f64,
    pub threshold_pct: u8,
}

/// Pure threshold check. `Some(alert)` when `reading.pressure_pct() >=
/// threshold_pct` (and `total > 0`); `None` otherwise. The comparison is
/// `>=` so a threshold of 90 fires at exactly 90%.
pub fn evaluate_pressure(reading: VramReading, threshold_pct: u8) -> Option<PressureAlert> {
    if reading.total_mib == 0 {
        return None;
    }
    let pct = reading.pressure_pct();
    if pct >= f64::from(threshold_pct) {
        Some(PressureAlert {
            used_mib: reading.used_mib,
            total_mib: reading.total_mib,
            pct,
            threshold_pct,
        })
    } else {
        None
    }
}

/// Parse one `nvidia-smi --query-gpu=memory.used,memory.total
/// --format=csv,noheader,nounits` line (e.g. `"1234, 8192"`) into a
/// reading. `None` on a malformed / empty / single-field line.
pub fn parse_vram_used_total(line: &str) -> Option<VramReading> {
    let mut parts = line.split(',').map(str::trim);
    let used = parts.next()?.parse::<u32>().ok()?;
    let total = parts.next()?.parse::<u32>().ok()?;
    Some(VramReading {
        used_mib: used,
        total_mib: total,
    })
}

/// Parse `rocm-smi --showmeminfo vram --csv` output for the FIRST GPU.
/// AMD's `rocm-smi` reports VRAM in BYTES (unlike `nvidia-smi`'s MiB), so
/// the byte columns are converted to MiB (÷ 1024²) to match
/// [`VramReading`]. Accepts the CSV form whose header carries
/// `vram total memory (b)` + `vram used memory (b)` columns, e.g.:
/// ```text
/// device,VRAM Total Memory (B),VRAM Total Used Memory (B)
/// card0,17163091968,1080033280
/// ```
/// Returns `None` on a missing column / unparseable / empty body, or a
/// zero total (degenerate). Column order is resolved from the header so a
/// future `rocm-smi` column-reorder doesn't silently misread.
pub fn parse_amd_vram_csv(text: &str) -> Option<VramReading> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next()?.to_ascii_lowercase();
    let cols: Vec<&str> = header.split(',').map(str::trim).collect();
    let total_idx = cols.iter().position(|c| c.contains("vram total memory"))?;
    let used_idx = cols
        .iter()
        .position(|c| c.contains("vram total used memory") || c.contains("vram used memory"))?;
    let row = lines.next()?;
    let fields: Vec<&str> = row.split(',').map(str::trim).collect();
    let total_bytes = fields.get(total_idx)?.parse::<u64>().ok()?;
    let used_bytes = fields.get(used_idx)?.parse::<u64>().ok()?;
    if total_bytes == 0 {
        return None;
    }
    const MIB: u64 = 1024 * 1024;
    Some(VramReading {
        used_mib: (used_bytes / MIB) as u32,
        total_mib: (total_bytes / MIB) as u32,
    })
}

/// Best-effort live read of the FIRST GPU's VRAM via `nvidia-smi`.
/// `None` on any failure (binary absent, non-zero exit, non-NVIDIA host,
/// parse miss) — the cron treats that as "no GPU pressure to report".
fn read_nvidia_vram() -> Option<VramReading> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // First GPU line wins — single-GPU is the common case; per-card
    // multi-GPU pressure is a follow-on.
    text.lines().next().and_then(parse_vram_used_total)
}

/// Best-effort live read of the FIRST GPU's VRAM via AMD's `rocm-smi`.
/// `None` on any failure (binary absent, non-zero exit, non-AMD host,
/// parse miss) — same advisory-only contract as [`read_nvidia_vram`].
fn read_amd_vram() -> Option<VramReading> {
    let out = std::process::Command::new("rocm-smi")
        .args(["--showmeminfo", "vram", "--csv"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_amd_vram_csv(&text)
}

/// Vendor-agnostic VRAM probe: try NVIDIA (`nvidia-smi`) first, then AMD
/// (`rocm-smi`). The first vendor whose tool is present + parses wins;
/// `None` on a host with neither (CPU-only / Intel-integrated / no GPU
/// tooling) — the watcher is then a clean no-op. Intel discrete (Arc)
/// has no `nvidia-smi`/`rocm-smi` equivalent (its `intel_gpu_top` JSON is
/// a separate, messier slice) so it is intentionally not probed here.
/// `pub(crate)` so the hardware probe (SL-03 — `neoth hardware`) can include a
/// live VRAM reading alongside the static accelerator capability info.
pub(crate) fn read_gpu_vram() -> Option<VramReading> {
    read_nvidia_vram().or_else(read_amd_vram)
}

/// One watcher tick. `reading` is INJECTED so the tick is unit-testable
/// (the live loop passes [`read_gpu_vram`]). On a breach it emits a
/// `0x47 RESOURCE_PRESSURE_ALERT` frame + returns `Ok(Some(alert))`;
/// otherwise (no reading / under threshold) `Ok(None)` with no frame.
pub async fn run_resource_watch_tick(
    config: &ResourceWatchConfig,
    writer: &WalWriterHandle,
    reading: Option<VramReading>,
) -> Result<Option<PressureAlert>, String> {
    let Some(reading) = reading else {
        return Ok(None);
    };
    let Some(alert) = evaluate_pressure(reading, config.vram_threshold_pct) else {
        return Ok(None);
    };
    let ts_unix = crate::time::now_unix_i64();
    let payload = serde_json::to_vec(&serde_json::json!({
        "used_mib": alert.used_mib,
        "total_mib": alert.total_mib,
        "pct": alert.pct,
        "threshold_pct": alert.threshold_pct,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize pressure payload: {e}"))?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_RESOURCE_PRESSURE_ALERT,
        &payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    writer
        .append(header, payload)
        .await
        .map_err(|e| format!("wal append: {e}"))?;
    tracing::warn!(
        used_mib = alert.used_mib,
        total_mib = alert.total_mib,
        pct = alert.pct,
        threshold_pct = alert.threshold_pct,
        "resource pressure: VRAM over threshold — `neoth wal show --type resource_pressure_alert`",
    );
    Ok(Some(alert))
}

/// Spawn the resource-watch cron loop. Returns the `JoinHandle` so the
/// daemon tracks it; `None` when `config.enabled == false` (the default)
/// so opt-out operators carry no idle task. Interval is clamped to a 10s
/// floor by [`ResourceWatchConfig::interval_duration`].
pub fn spawn_resource_watch_loop(
    config: ResourceWatchConfig,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("resource-watch cron disabled (resource_watch.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            vram_threshold_pct = config.vram_threshold_pct,
            "resource-watch cron loop online (SL-03)",
        );
        loop {
            ticker.tick().await;
            let reading = read_gpu_vram();
            match run_resource_watch_tick(&config, &writer, reading).await {
                Ok(Some(a)) => {
                    tracing::info!(pct = a.pct, "resource-watch: 0x47 emitted")
                }
                Ok(None) => tracing::debug!("resource-watch: no pressure this tick"),
                Err(e) => tracing::error!(error = %e, "resource-watch tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_RESOURCE_PRESSURE_ALERT;

    fn enabled_config(threshold: u8) -> ResourceWatchConfig {
        ResourceWatchConfig {
            enabled: true,
            interval_secs: 30,
            vram_threshold_pct: threshold,
        }
    }

    /// Count `0x47` frames in an uncompressed WAL segment (test writer
    /// uses the plain `spawn`). Missing file (no append happened) → 0.
    fn count_pressure_frames(seg: &std::path::Path) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_RESOURCE_PRESSURE_ALERT {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    #[test]
    fn pressure_pct_is_used_over_total() {
        assert!(
            (VramReading {
                used_mib: 4096,
                total_mib: 8192
            }
            .pressure_pct()
                - 50.0)
                .abs()
                < 1e-9
        );
        // Degenerate / no-GPU total=0 → 0.0, never a div-by-zero.
        assert_eq!(
            VramReading {
                used_mib: 100,
                total_mib: 0
            }
            .pressure_pct(),
            0.0
        );
    }

    #[test]
    fn evaluate_pressure_fires_at_or_over_threshold() {
        // 7400/8192 = 90.3% >= 90 → Some.
        assert!(
            evaluate_pressure(
                VramReading {
                    used_mib: 7400,
                    total_mib: 8192
                },
                90
            )
            .is_some()
        );
        // 4096/8192 = 50% < 90 → None.
        assert!(
            evaluate_pressure(
                VramReading {
                    used_mib: 4096,
                    total_mib: 8192
                },
                90
            )
            .is_none()
        );
        // Exactly at threshold (90/100) → Some (>=).
        let at = evaluate_pressure(
            VramReading {
                used_mib: 90,
                total_mib: 100,
            },
            90,
        )
        .expect("exactly-at-threshold fires");
        assert_eq!(at.threshold_pct, 90);
        assert!((at.pct - 90.0).abs() < 1e-9);
        // total=0 → never fires.
        assert!(
            evaluate_pressure(
                VramReading {
                    used_mib: 5,
                    total_mib: 0
                },
                90
            )
            .is_none()
        );
    }

    #[test]
    fn parse_vram_line_handles_real_and_malformed() {
        assert_eq!(
            parse_vram_used_total("1234, 8192"),
            Some(VramReading {
                used_mib: 1234,
                total_mib: 8192
            })
        );
        // nvidia-smi nounits with no space after comma.
        assert_eq!(
            parse_vram_used_total("500,2000"),
            Some(VramReading {
                used_mib: 500,
                total_mib: 2000
            })
        );
        assert!(parse_vram_used_total("garbage").is_none());
        assert!(parse_vram_used_total("").is_none());
        assert!(parse_vram_used_total("1234").is_none()); // single field
        assert!(parse_vram_used_total("a, b").is_none()); // non-numeric
    }

    #[test]
    fn parse_amd_vram_csv_converts_bytes_to_mib() {
        // rocm-smi reports BYTES. 17163091968 B = 16368 MiB, 1080033280 B = 1030 MiB.
        let csv = "device,VRAM Total Memory (B),VRAM Total Used Memory (B)\n\
                   card0,17163091968,1080033280\n";
        let r = parse_amd_vram_csv(csv).expect("real rocm-smi csv parses");
        assert_eq!(r.total_mib, 16368);
        assert_eq!(r.used_mib, 1030);
    }

    #[test]
    fn parse_amd_vram_csv_resolves_column_order_from_header() {
        // Columns reordered (used before total) — header lookup must still
        // map each value correctly, not assume positional order.
        let csv = "VRAM Total Used Memory (B),device,VRAM Total Memory (B)\n\
                   524288000,card0,1048576000\n";
        let r = parse_amd_vram_csv(csv).expect("reordered csv parses");
        assert_eq!(r.total_mib, 1000); // 1048576000 / 1048576
        assert_eq!(r.used_mib, 500); // 524288000 / 1048576
    }

    #[test]
    fn parse_amd_vram_csv_rejects_malformed() {
        assert!(parse_amd_vram_csv("").is_none()); // empty
        assert!(parse_amd_vram_csv("device,foo,bar\ncard0,1,2\n").is_none()); // no vram cols
        // header present but no data row.
        assert!(
            parse_amd_vram_csv("device,VRAM Total Memory (B),VRAM Total Used Memory (B)\n")
                .is_none()
        );
        // non-numeric byte value.
        assert!(
            parse_amd_vram_csv(
                "device,VRAM Total Memory (B),VRAM Total Used Memory (B)\ncard0,xx,1080033280\n"
            )
            .is_none()
        );
        // zero total → degenerate, never a div-by-zero downstream.
        assert!(
            parse_amd_vram_csv(
                "device,VRAM Total Memory (B),VRAM Total Used Memory (B)\ncard0,0,0\n"
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn tick_no_reading_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("rw.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_resource_watch_tick(&enabled_config(90), &writer, None)
            .await
            .unwrap();
        assert!(out.is_none());
        assert_eq!(count_pressure_frames(&seg), 0);
    }

    #[tokio::test]
    async fn tick_under_threshold_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("rw.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_resource_watch_tick(
            &enabled_config(90),
            &writer,
            Some(VramReading {
                used_mib: 4096,
                total_mib: 8192,
            }),
        )
        .await
        .unwrap();
        assert!(out.is_none());
        assert_eq!(count_pressure_frames(&seg), 0);
    }

    #[tokio::test]
    async fn tick_over_threshold_emits_one_frame() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("rw.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let alert = run_resource_watch_tick(
            &enabled_config(90),
            &writer,
            Some(VramReading {
                used_mib: 7900,
                total_mib: 8192,
            }),
        )
        .await
        .unwrap()
        .expect("over threshold must alert");
        assert_eq!(alert.threshold_pct, 90);
        assert!(alert.pct > 90.0);
        assert_eq!(count_pressure_frames(&seg), 1, "exactly one 0x47 frame");
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("rw.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = ResourceWatchConfig {
            enabled: false,
            interval_secs: 30,
            vram_threshold_pct: 90,
        };
        assert!(spawn_resource_watch_loop(cfg, writer).is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("rw.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let handle =
            spawn_resource_watch_loop(enabled_config(90), writer).expect("enabled → join handle");
        handle.abort();
    }
}
