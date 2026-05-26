//! Rolling-window provider metering — Q-3 adoption.
//!
//! Ports hermes' `metering.py` shape into pure-Rust: every
//! `provider.complete()` records an event {ts, input_tokens, output_tokens,
//! latency_ns}. A bounded VecDeque keeps the last `window` of events; older
//! entries fall off the back. Read-side computes per-second token rates +
//! latency percentiles from the live window.
//!
//! Used by `daemon/observability.rs` to surface throughput in the snapshot
//! and (later) by the Cerebellum motor-view planner — it picks up the same
//! Meter via a WAL-replay path so the metrics survive daemon restarts.
//!
//! Design pins:
//!   - `Meter::record` is sync + non-blocking — no locks beyond the parking
//!     mutex behind `Arc<Mutex<Inner>>`. Hot path stays cheap.
//!   - Window is wall-clock-bounded, not count-bounded — a quiet hour
//!     correctly reports near-zero TPS instead of stale numbers from an
//!     hour ago.
//!   - Percentile reads scan the window in `O(n)` and sort a copy. With
//!     `DEFAULT_WINDOW = 60s` and typical < 1 req/sec, this is < 100 floats.
//!
//! Trigger for upgrade to histogram: window outgrows ~1000 events per
//! second sustained.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default window — 60 seconds. Matches the Jarvis `metering.py` constant.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// One recorded provider-call event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Event {
    /// Monotonic timestamp — `Instant::now()` at record time.
    pub at: Instant,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub latency: Duration,
}

/// Read-side snapshot. Serialisable later for `/metrics` Prometheus output.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    /// Total events still inside the rolling window.
    pub sample_count: usize,
    /// Average input tokens per second across the window.
    pub input_tps: f64,
    /// Average output tokens per second across the window.
    pub output_tps: f64,
    /// 50th-percentile latency (median).
    pub p50_latency_ms: f64,
    /// 95th-percentile latency.
    pub p95_latency_ms: f64,
}

#[derive(Debug)]
struct Inner {
    window: Duration,
    events: VecDeque<Event>,
}

/// Cheaply-clonable handle — multiple call sites (provider dispatch,
/// observability snapshot, …) share one underlying buffer.
#[derive(Clone, Debug)]
pub struct Meter {
    inner: Arc<Mutex<Inner>>,
}

impl Meter {
    pub fn new(window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                window,
                events: VecDeque::new(),
            })),
        }
    }

    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_WINDOW)
    }

    /// Record one provider-call event. Drops any events older than `window`
    /// before adding the new one — keeps the buffer bounded without a
    /// separate prune task.
    pub fn record(&self, input_tokens: u32, output_tokens: u32, latency: Duration) {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            let window = g.window;
            // Drain expired entries.
            let cutoff = now.checked_sub(window).unwrap_or(now);
            while let Some(front) = g.events.front() {
                if front.at < cutoff {
                    g.events.pop_front();
                } else {
                    break;
                }
            }
            g.events.push_back(Event {
                at: now,
                input_tokens,
                output_tokens,
                latency,
            });
        }
    }

    /// Compute a snapshot from the current window. Returns zero-filled
    /// fields when the window is empty so callers can render without a
    /// special case.
    pub fn snapshot(&self) -> Snapshot {
        let now = Instant::now();
        let Ok(g) = self.inner.lock() else {
            return Snapshot {
                sample_count: 0,
                input_tps: 0.0,
                output_tps: 0.0,
                p50_latency_ms: 0.0,
                p95_latency_ms: 0.0,
            };
        };
        let window = g.window;
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let alive: Vec<&Event> = g.events.iter().filter(|e| e.at >= cutoff).collect();
        let sample_count = alive.len();
        if sample_count == 0 {
            return Snapshot {
                sample_count: 0,
                input_tps: 0.0,
                output_tps: 0.0,
                p50_latency_ms: 0.0,
                p95_latency_ms: 0.0,
            };
        }

        let total_in: u64 = alive.iter().map(|e| e.input_tokens as u64).sum();
        let total_out: u64 = alive.iter().map(|e| e.output_tokens as u64).sum();
        let window_secs = window.as_secs_f64().max(1.0);

        let mut latencies_ms: Vec<f64> = alive
            .iter()
            .map(|e| e.latency.as_secs_f64() * 1000.0)
            .collect();
        latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = percentile(&latencies_ms, 0.50);
        let p95 = percentile(&latencies_ms, 0.95);

        Snapshot {
            sample_count,
            input_tps: total_in as f64 / window_secs,
            output_tps: total_out as f64 / window_secs,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
        }
    }

    /// Test-only accessor — count live events without rendering a snapshot.
    #[cfg(test)]
    pub fn live_count(&self) -> usize {
        self.inner.lock().map(|g| g.events.len()).unwrap_or(0)
    }
}

impl Snapshot {
    /// R-03 (Session 24) — operator-facing one-line chat header.
    /// Returns `None` for a cold meter (zero samples) so the chat
    /// path can suppress the header line entirely on the very first
    /// turn instead of printing `[meter] 0.0 tps … 0 samples`,
    /// which is just noise.
    ///
    /// Format: `[meter] {out_tps:.1} tps out · p50 {p50_ms:.0}ms · {n} samples`
    ///
    /// Lives on `Snapshot` (not `Meter`) so callers that already
    /// captured a snapshot don't have to lock the meter twice.
    pub fn chat_header_line(&self) -> Option<String> {
        if self.sample_count == 0 {
            return None;
        }
        Some(format!(
            "[meter] {tps:.1} tps out · p50 {p50:.0}ms · {n} samples",
            tps = self.output_tps,
            p50 = self.p50_latency_ms,
            n = self.sample_count,
        ))
    }
}

/// Linear-interpolated percentile over a sorted slice. Empty → 0.0.
fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let pos = q * (n as f64 - 1.0);
    let lower = pos.floor() as usize;
    let upper = pos.ceil() as usize;
    if lower == upper {
        return sorted[lower];
    }
    let frac = pos - lower as f64;
    sorted[lower] + (sorted[upper] - sorted[lower]) * frac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_meter_snapshot_is_zero_filled() {
        let m = Meter::with_default_window();
        let s = m.snapshot();
        assert_eq!(s.sample_count, 0);
        assert_eq!(s.input_tps, 0.0);
        assert_eq!(s.output_tps, 0.0);
        assert_eq!(s.p50_latency_ms, 0.0);
        assert_eq!(s.p95_latency_ms, 0.0);
    }

    #[test]
    fn single_event_shows_in_snapshot() {
        let m = Meter::with_default_window();
        m.record(100, 50, Duration::from_millis(250));
        let s = m.snapshot();
        assert_eq!(s.sample_count, 1);
        // Single sample → p50 == p95 == 250ms (no interpolation).
        assert!((s.p50_latency_ms - 250.0).abs() < 1e-6);
        assert!((s.p95_latency_ms - 250.0).abs() < 1e-6);
        // 100 input tokens over 60s = 100/60 = 1.666... tps.
        assert!((s.input_tps - 100.0 / 60.0).abs() < 1e-6);
        assert!((s.output_tps - 50.0 / 60.0).abs() < 1e-6);
    }

    #[test]
    fn percentile_interpolates_between_neighbours() {
        let sorted = [10.0, 20.0, 30.0, 40.0, 50.0];
        // p50 over 5 elements: pos = 0.5*(5-1) = 2.0 → sorted[2] = 30.
        assert!((percentile(&sorted, 0.50) - 30.0).abs() < 1e-6);
        // p25: pos = 1.0 → sorted[1] = 20.
        assert!((percentile(&sorted, 0.25) - 20.0).abs() < 1e-6);
        // p95: pos = 0.95*4 = 3.8 → 40 + 0.8*(50-40) = 48.
        assert!((percentile(&sorted, 0.95) - 48.0).abs() < 1e-6);
    }

    #[test]
    fn old_events_prune_on_record() {
        // Tiny 100ms window so the test runs fast.
        let m = Meter::new(Duration::from_millis(100));
        m.record(10, 10, Duration::from_millis(10));
        assert_eq!(m.live_count(), 1);
        std::thread::sleep(Duration::from_millis(150));
        // Recording again must prune the expired entry.
        m.record(20, 20, Duration::from_millis(15));
        assert_eq!(m.live_count(), 1, "expired entry should have been dropped");
        let s = m.snapshot();
        assert_eq!(s.sample_count, 1);
    }

    #[test]
    fn snapshot_ignores_expired_without_record_pruning() {
        let m = Meter::new(Duration::from_millis(50));
        m.record(5, 5, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(80));
        // No new record → live_count still shows the buffered entry, but
        // snapshot's read-side filter excludes it.
        let s = m.snapshot();
        assert_eq!(s.sample_count, 0);
    }

    #[test]
    fn meter_is_cheaply_clonable_handle() {
        let a = Meter::with_default_window();
        let b = a.clone();
        a.record(1, 2, Duration::from_millis(10));
        // Both handles see the same underlying buffer.
        assert_eq!(a.live_count(), 1);
        assert_eq!(b.live_count(), 1);
    }

    #[test]
    fn percentiles_on_three_samples() {
        let m = Meter::with_default_window();
        m.record(10, 10, Duration::from_millis(100));
        m.record(20, 20, Duration::from_millis(200));
        m.record(30, 30, Duration::from_millis(300));
        let s = m.snapshot();
        assert_eq!(s.sample_count, 3);
        // Sorted latencies: [100, 200, 300]. p50 = 200ms exact.
        assert!(
            (s.p50_latency_ms - 200.0).abs() < 1e-6,
            "got {}",
            s.p50_latency_ms
        );
        // p95: pos = 0.95*2 = 1.9 → 200 + 0.9*100 = 290ms.
        assert!(
            (s.p95_latency_ms - 290.0).abs() < 1e-6,
            "got {}",
            s.p95_latency_ms
        );
    }

    // ── R-03 (Session 24) chat-header formatter ───────────────────────

    #[test]
    fn r_03_chat_header_returns_none_for_cold_meter() {
        // First chat turn after daemon boot — meter is empty, header
        // must suppress instead of printing a noise line.
        let snap = Meter::with_default_window().snapshot();
        assert!(snap.chat_header_line().is_none());
    }

    #[test]
    fn r_03_chat_header_renders_with_samples() {
        let m = Meter::with_default_window();
        m.record(120, 600, Duration::from_millis(800));
        let snap = m.snapshot();
        let line = snap.chat_header_line().expect("samples → Some");
        assert!(line.starts_with("[meter] "));
        // 600 out tokens over 60s = 10.0 tps. Format pins to 1 decimal.
        assert!(line.contains("10.0 tps out"), "got {line}");
        assert!(line.contains("p50 800ms"), "got {line}");
        assert!(line.contains("1 samples"), "got {line}");
    }

    #[test]
    fn r_03_chat_header_format_is_stable_across_decimal_widths() {
        // Drift guard: a refactor that drops the `:.1` / `:.0` width
        // specifiers would surface as a verbose float string.
        let m = Meter::with_default_window();
        m.record(0, 1, Duration::from_secs(1));
        let line = m.snapshot().chat_header_line().unwrap();
        // No exponent notation; no more than 4 decimals on tps.
        assert!(!line.contains("e-"), "scientific notation leaked: {line}");
        let tps_chunk = line
            .split('·')
            .next()
            .unwrap()
            .trim()
            .strip_prefix("[meter] ")
            .unwrap();
        let dot_idx = tps_chunk.find('.').unwrap();
        let decimals = tps_chunk[dot_idx + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .count();
        assert_eq!(
            decimals, 1,
            "tps must render with exactly 1 decimal: {line}"
        );
    }
}
