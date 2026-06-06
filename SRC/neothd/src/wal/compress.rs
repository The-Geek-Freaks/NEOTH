// WAL segment compression helpers — Workstream F (CT-10/E-20/V1x-06).
//
// These are pure-sync wrappers around `zstd`. They operate on the *frame body*
// of a sealed segment — the bytes AFTER the segment header. The header is never
// compressed; only the frame payload bytes are affected.
//
// Compression level 3 is the spec-mandated choice (HANDOFF §Workstream-F):
// good ratio on JSON-heavy WAL payloads at low latency, well within the range
// of "negligible finalization overhead" for segments that rotate at 16 MiB / 24h.

use crate::wal::error::WalError;

/// Compression level used for all v2 compressed segments.
pub const ZSTD_LEVEL: i32 = 3;

/// Hard ceiling on the decompressed size of a single segment frame body
/// (GOLD-SEC-11 / A-29). Segments rotate at 16 MiB, so 256 MiB is ~16×
/// headroom for any legitimate segment while refusing a zip-bomb: a tiny
/// crafted `.bin` that would otherwise expand unbounded and OOM the daemon.
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Compress `frames` using zstd level-3. Returns the compressed bytes.
///
/// Called by the writer on segment finalize when
/// `freedom.yaml::wal.compression == "zstd_3"`.
pub fn compress_frames(frames: &[u8]) -> Result<Vec<u8>, WalError> {
    zstd::encode_all(frames, ZSTD_LEVEL).map_err(|e| WalError::Compress(e.to_string()))
}

/// Decompress a zstd-compressed frame body. Returns the raw WAL frames.
///
/// Called by the reader (and migrate tool) when
/// `SegmentHeaderV2.flags & SEGMENT_FLAG_COMPRESSED != 0`.
pub fn decompress_frames(compressed: &[u8]) -> Result<Vec<u8>, WalError> {
    decompress_frames_capped(compressed, MAX_DECOMPRESSED_BYTES)
}

/// [`decompress_frames`] with an explicit output cap. Stream-decodes with
/// a hard ceiling so a maliciously-crafted compressed segment cannot
/// expand unbounded and OOM the daemon (GOLD-SEC-11 / A-29). Reads one
/// byte past `max` to detect overflow.
fn decompress_frames_capped(compressed: &[u8], max: u64) -> Result<Vec<u8>, WalError> {
    use std::io::Read;
    let mut decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| WalError::Decompress(e.to_string()))?;
    let mut out = Vec::new();
    let n = decoder
        .by_ref()
        .take(max + 1)
        .read_to_end(&mut out)
        .map_err(|e| WalError::Decompress(e.to_string()))?;
    if n as u64 > max {
        return Err(WalError::Decompress(format!(
            "decompressed segment exceeds the {max}-byte cap — refusing (decompression-bomb guard)"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic JSON-heavy WAL payload — the kind produced by provider /
    /// chat / telemetry events. Used by multiple tests below.
    fn json_payload(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let chunk = br#"{"event_type":"PROVIDER_RESPONSE","ts_ns":1700000000000000000,"payload":{"role":"assistant","content":"Hello, world! This is a test payload for compression ratio verification.","tokens":42}}"#;
        while v.len() < n {
            let take = (n - v.len()).min(chunk.len());
            v.extend_from_slice(&chunk[..take]);
        }
        v
    }

    // ── v1: roundtrip compress + decompress ──────────────────────────────────

    #[test]
    fn roundtrip_small_payload() {
        let input = b"hello WAL world".to_vec();
        let compressed = compress_frames(&input).expect("compress");
        let restored = decompress_frames(&compressed).expect("decompress");
        assert_eq!(restored, input);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let input = b"".to_vec();
        let compressed = compress_frames(&input).expect("compress empty");
        let restored = decompress_frames(&compressed).expect("decompress empty");
        assert_eq!(restored, input);
    }

    #[test]
    fn roundtrip_json_heavy_payload() {
        let input = json_payload(10_240); // 10 KiB
        let compressed = compress_frames(&input).expect("compress json");
        let restored = decompress_frames(&compressed).expect("decompress json");
        assert_eq!(restored, input);
    }

    // ── v2: compression ratio sanity ────────────────────────────────────────

    #[test]
    fn compression_ratio_under_30_pct_on_json_payload() {
        // Spec requirement (HANDOFF §Workstream-F): 10 KiB JSON-heavy payload
        // must compress to < 30% of the original size at level 3.
        let input = json_payload(10_240);
        let compressed = compress_frames(&input).expect("compress");
        let ratio = compressed.len() as f64 / input.len() as f64;
        assert!(
            ratio < 0.30,
            "expected compressed/original < 30%, got {:.1}% ({} / {} bytes)",
            ratio * 100.0,
            compressed.len(),
            input.len(),
        );
    }

    // ── error path ──────────────────────────────────────────────────────────

    #[test]
    fn decompress_rejects_output_over_cap() {
        // GOLD-SEC-11 / A-29: a payload that decompresses beyond the cap is
        // refused (not OOM'd). Tested with a tiny cap to avoid a 256 MiB alloc.
        let input = json_payload(10_240); // decompresses to 10 KiB
        let compressed = compress_frames(&input).expect("compress");
        let err = decompress_frames_capped(&compressed, 100).unwrap_err();
        assert!(
            matches!(err, WalError::Decompress(_)),
            "over-cap decompress must error, got {err:?}"
        );
        // A generous cap still round-trips.
        let ok = decompress_frames_capped(&compressed, 1_000_000).expect("under-cap ok");
        assert_eq!(ok, input);
    }

    #[test]
    fn decompress_garbage_returns_error() {
        let garbage = b"this is not a zstd frame at all".to_vec();
        let err = decompress_frames(&garbage).unwrap_err();
        // Must be a Decompress variant, not a panic.
        assert!(
            matches!(err, WalError::Decompress(_)),
            "expected WalError::Decompress, got {err:?}"
        );
    }
}
