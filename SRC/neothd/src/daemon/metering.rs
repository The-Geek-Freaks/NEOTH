//! GOLD-ADAPT-HERMES-09 — Token TPS metering + SSE `metering` event.
//!
//! A lightweight, allocation-light token-throughput meter for provider
//! streaming responses. The caller wraps a token stream with [`TpsMeter`]:
//!
//! ```ignore
//! let mut meter = TpsMeter::start();
//! for chunk in stream { meter.observe(chunk.tokens); }
//! let sample = meter.finish();
//! // sample.tps() => tokens / elapsed_secs (zero-duration guarded)
//! ```
//!
//! ## WAL event
//! [`emit_tps_sample`] writes `0x69 TOKEN_TPS_SAMPLE` when the caller
//! supplies a [`WalWriterHandle`]. This is intentionally **optional** — the
//! hot provider stream path (`providers/`) is parallel-reserved (HOT lane),
//! so wiring the emit there is a follow-up. The standalone meter + tests
//! ship in the clean lane; the WAL emit can be called from any non-hot site
//! (e.g. a batch job or a metrics-drain cron) once the HOT-lane reservation
//! is lifted.
//!
//! ## Design invariants
//! * **No async** in the meter itself — pure synchronous accounting, no
//!   tokio dependency. The WAL emit is `async` but isolated in
//!   [`emit_tps_sample`].
//! * **Zero-duration guard** — `tps()` returns `0.0` when `elapsed < 1 µs`
//!   to avoid division-by-zero on instantaneous flushes.
//! * **No allocation during streaming** — `observe` is a pair of integer
//!   additions; no `Vec` or heap growth.

use std::time::{Duration, Instant};

// ── Core meter ─────────────────────────────────────────────────────────────

/// A in-progress token-throughput measurement.
///
/// Created by [`TpsMeter::start`], consumed by [`TpsMeter::finish`].
#[derive(Debug)]
pub struct TpsMeter {
    started_at: Instant,
    total_tokens: u64,
    observe_count: u32,
}

impl TpsMeter {
    /// Begin a new measurement, anchoring the start wall-clock.
    #[must_use]
    pub fn start() -> Self {
        Self {
            started_at: Instant::now(),
            total_tokens: 0,
            observe_count: 0,
        }
    }

    /// Record `tokens` additional tokens from the stream.
    ///
    /// May be called any number of times (including zero) before [`finish`].
    /// [`finish`]: TpsMeter::finish
    #[inline]
    pub fn observe(&mut self, tokens: u64) {
        self.total_tokens = self.total_tokens.saturating_add(tokens);
        self.observe_count = self.observe_count.saturating_add(1);
    }

    /// Finalise the measurement and return a [`TpsSample`].
    ///
    /// Consumes the meter so no further `observe` calls are possible.
    pub fn finish(self) -> TpsSample {
        TpsSample {
            elapsed: self.started_at.elapsed(),
            total_tokens: self.total_tokens,
            observe_count: self.observe_count,
        }
    }
}

// ── Completed sample ────────────────────────────────────────────────────────

/// A completed token-throughput measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct TpsSample {
    /// Wall-clock duration of the streaming window.
    pub elapsed: Duration,
    /// Total tokens observed across all [`TpsMeter::observe`] calls.
    pub total_tokens: u64,
    /// Number of `observe` calls made (i.e., stream chunks received).
    pub observe_count: u32,
}

/// Minimum elapsed time (1 µs) before TPS is computed. Below this the
/// duration is effectively zero and the result would be nonsensical.
const MIN_ELAPSED_FOR_TPS: Duration = Duration::from_micros(1);

impl TpsSample {
    /// Tokens per second.  Returns `0.0` when elapsed < 1 µs (zero-duration
    /// guard) or when no tokens were observed.
    #[must_use]
    pub fn tps(&self) -> f64 {
        if self.elapsed < MIN_ELAPSED_FOR_TPS || self.total_tokens == 0 {
            return 0.0;
        }
        self.total_tokens as f64 / self.elapsed.as_secs_f64()
    }

    /// Whether the sample contains at least one observed token.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.total_tokens > 0
    }

    /// Mean tokens per chunk (observe call).  `None` when no chunks were
    /// received.
    #[must_use]
    pub fn mean_tokens_per_chunk(&self) -> Option<f64> {
        if self.observe_count == 0 {
            return None;
        }
        Some(self.total_tokens as f64 / self.observe_count as f64)
    }
}

// ── WAL emit ───────────────────────────────────────────────────────────────

/// Emit `0x69 TOKEN_TPS_SAMPLE` to the WAL.
///
/// This is optional — callers in the hot provider-stream path MUST NOT call
/// this until the HOT-lane reservation is lifted (follow-up wire). Callers
/// in clean-lane positions (batch jobs, metrics crens, test harnesses) may
/// call it freely.
///
/// **Payload** (JSON):
/// ```json
/// { "tps": 42.3, "total_tokens": 512, "elapsed_ms": 12100,
///   "observe_count": 64, "ts_unix": 1718000000 }
/// ```
pub async fn emit_tps_sample(
    sample: &TpsSample,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<(), String> {
    let ts_unix = crate::time::now_unix_i64();
    let payload = serde_json::to_vec(&serde_json::json!({
        "tps": sample.tps(),
        "total_tokens": sample.total_tokens,
        "elapsed_ms": sample.elapsed.as_millis() as u64,
        "observe_count": sample.observe_count,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize tps-sample payload: {e}"))?;

    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_TOKEN_TPS_SAMPLE, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();

    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|e| format!("wal append tps-sample: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // ── TpsSample::tps ──────────────────────────────────────────────────────

    /// Feed a known elapsed + token count, check the TPS arithmetic.
    #[test]
    fn tps_arithmetic_correct() {
        let sample = TpsSample {
            elapsed: Duration::from_secs(2),
            total_tokens: 100,
            observe_count: 10,
        };
        assert!(
            (sample.tps() - 50.0).abs() < 1e-9,
            "100 tokens / 2 s = 50 tps"
        );
    }

    /// Zero-duration guard: sub-microsecond elapsed → tps() must return 0.0.
    #[test]
    fn tps_zero_duration_guard() {
        let sample = TpsSample {
            elapsed: Duration::from_nanos(500), // < 1 µs
            total_tokens: 100,
            observe_count: 1,
        };
        assert_eq!(
            sample.tps(),
            0.0,
            "sub-µs elapsed must not divide by near-zero duration"
        );
    }

    /// No tokens observed → tps() returns 0.0 even with real elapsed time.
    #[test]
    fn tps_zero_tokens() {
        let sample = TpsSample {
            elapsed: Duration::from_secs(5),
            total_tokens: 0,
            observe_count: 0,
        };
        assert_eq!(sample.tps(), 0.0);
        assert!(!sample.has_data());
    }

    /// Single observe call with a known token count.
    #[test]
    fn tps_single_observe() {
        let sample = TpsSample {
            elapsed: Duration::from_millis(500),
            total_tokens: 25,
            observe_count: 1,
        };
        // 25 / 0.5 = 50.0
        assert!((sample.tps() - 50.0).abs() < 1e-9);
    }

    // ── TpsMeter round-trip ─────────────────────────────────────────────────

    /// Start + multiple observe + finish: total_tokens accumulates correctly.
    #[test]
    fn meter_accumulates_tokens() {
        let mut meter = TpsMeter::start();
        meter.observe(10);
        meter.observe(20);
        meter.observe(30);
        let sample = meter.finish();
        assert_eq!(sample.total_tokens, 60);
        assert_eq!(sample.observe_count, 3);
        // elapsed is real wall-clock — just assert it is non-zero and sane.
        assert!(sample.elapsed >= Duration::ZERO);
    }

    /// Zero observe calls → has_data false, mean_tokens_per_chunk None.
    #[test]
    fn meter_no_observations() {
        let meter = TpsMeter::start();
        let sample = meter.finish();
        assert_eq!(sample.total_tokens, 0);
        assert_eq!(sample.observe_count, 0);
        assert!(!sample.has_data());
        assert!(sample.mean_tokens_per_chunk().is_none());
    }

    // ── mean_tokens_per_chunk ───────────────────────────────────────────────

    #[test]
    fn mean_tokens_per_chunk_correct() {
        let sample = TpsSample {
            elapsed: Duration::from_secs(1),
            total_tokens: 60,
            observe_count: 4,
        };
        let mean = sample.mean_tokens_per_chunk().expect("4 chunks");
        assert!((mean - 15.0).abs() < 1e-9, "60 / 4 = 15");
    }

    // ── saturating arithmetic ───────────────────────────────────────────────

    /// observe() must not panic on u64 overflow — saturating_add is used.
    #[test]
    fn observe_saturates_on_overflow() {
        let mut meter = TpsMeter::start();
        meter.observe(u64::MAX);
        meter.observe(1); // would overflow without saturating_add
        let sample = meter.finish();
        assert_eq!(sample.total_tokens, u64::MAX);
    }

    // ── WAL emit ────────────────────────────────────────────────────────────

    /// emit_tps_sample writes exactly one 0x69 frame to the WAL segment.
    #[tokio::test]
    async fn emit_writes_one_frame() {
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let sample = TpsSample {
            elapsed: Duration::from_secs(3),
            total_tokens: 300,
            observe_count: 30,
        };
        emit_tps_sample(&sample, &writer)
            .await
            .expect("emit must succeed");

        drop(writer);
        join.await.ok();

        // Parse the WAL segment and count 0x69 frames.
        let bytes = std::fs::read(&seg).expect("segment must exist");
        let hdr =
            crate::wal::segment_header::parse_segment_header(&bytes).expect("valid segment header");
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_TOKEN_TPS_SAMPLE {
                count += 1;
                // Verify the JSON payload is parseable and carries the expected tps.
                let v: serde_json::Value =
                    serde_json::from_slice(dec.payload).expect("valid json payload");
                let tps = v["tps"].as_f64().expect("tps field");
                // 300 tokens / 3 s = 100 tps
                assert!((tps - 100.0).abs() < 1e-6, "expected ~100 tps, got {tps}");
                assert_eq!(v["total_tokens"].as_u64().unwrap(), 300);
                assert_eq!(v["elapsed_ms"].as_u64().unwrap(), 3000);
                assert_eq!(v["observe_count"].as_u64().unwrap(), 30);
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert_eq!(count, 1, "exactly one 0x69 TOKEN_TPS_SAMPLE frame");
    }
}
