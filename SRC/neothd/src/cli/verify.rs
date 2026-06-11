//! `neoth verify` — walk the WAL and check every HMAC compaction marker.
//! Phase 33b SP-2 payoff.
//!
//! Reads the segment(s) under `~/.neoth/wal/`, finds every
//! `COMPACTION_MARKER` frame, and recomputes the HMAC over the bytes
//! between `from_offset` and `to_offset`. Reports a clean pass or the
//! offending segment + offset on mismatch.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::compaction;

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Override the WAL directory (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub wal_dir: Option<PathBuf>,
    /// Override the HMAC key path.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,
    /// Verify only this specific segment file.
    #[arg(long, value_name = "PATH")]
    pub segment: Option<PathBuf>,
    /// SC-09 — verify only segments at/after the last HMAC-key rotation
    /// (`0xD9 HMAC_KEY_ROTATED`, written by `neoth security rewrap-hmac-key`).
    /// Markers in earlier segments were signed with a key that has since been
    /// replaced; skipping them avoids spurious failures after a key recovery.
    /// With no rotation recorded, verifies the full history (with a note).
    #[arg(long)]
    pub since_rotation: bool,
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// Reviewer-1 + Reviewer-2 P1-C refactor (2026-05-20): aggregate result
/// of verifying one or more WAL segments. The previous 113-line
/// `run_verify` did key handling + segment selection + marker extract
/// + authorisation extract + verification + reclassification + render
///   in one block; now each phase has its own helper and this struct
///   carries the result between them.
struct VerifyOutcome {
    total_markers: usize,
    total_verified: usize,
    failures: Vec<String>,
    reclassified: usize,
    authorised_count: usize,
}

pub async fn run_verify(args: VerifyArgs) -> Result<()> {
    let wal_dir = args
        .wal_dir
        .clone()
        .unwrap_or_else(FreedomConfig::default_wal_dir);
    let key_path = args
        .key
        .clone()
        .unwrap_or_else(compaction::default_key_path);
    let key = match compaction::load_or_init_key(&key_path) {
        Ok(k) => k,
        Err(e) => {
            // SC-09: a load failure here is almost always a DPAPI unwrap
            // failure after a machine swap / Windows reinstall / account
            // switch — point the operator straight at the recovery path
            // instead of a bare "load HMAC key" context.
            anyhow::bail!(
                "HMAC key at {} could not be loaded\n  cause: {e}\n  \
                 If the cause mentions CryptUnprotectData / a DPAPI unwrap failure, the key is \
                 bound to a DIFFERENT Windows user or machine (e.g. restored from a backup on \
                 another box).\n  \
                 Recovery (PLAN/RUNBOOK_dpapi_hmac_recovery.md): Tier 1 = re-wrap your plaintext \
                 backup with `neoth security rewrap-hmac-key --source <backup>`; Tier 2/3 = rotate \
                 or reset if no backup exists.",
                key_path.display()
            );
        }
    };

    let mut segments = if let Some(s) = args.segment.clone() {
        vec![s]
    } else {
        list_segments(&wal_dir)?
    };

    if args.since_rotation {
        segments = apply_since_rotation_filter(segments, args.output);
    }

    let authorised = collect_authorised_ranges(&segments)?;
    let outcome = verify_segments(&segments, &key, &authorised)?;
    render_verify_outcome(&segments, &outcome, args.output);

    if !outcome.failures.is_empty() {
        anyhow::bail!("{} marker(s) failed verification", outcome.failures.len());
    }
    Ok(())
}

/// Collect every authorised-redaction range from `REDACTION_MARKER`
/// (0xF3) frames across the supplied segments. Used by
/// [`verify_segments`] to reclassify HMAC mismatches that fall inside
/// an operator-authorised window as PASS-with-note.
fn collect_authorised_ranges(segments: &[PathBuf]) -> Result<Vec<AuthorisedRange>> {
    // Trust root for redaction exemptions = the operator's OWN ed25519 key, read
    // from `<wal_dir>/signing.key` (the segments' shared parent). `None` (no key
    // on disk) ⇒ no exemption can be authenticated ⇒ every 0xF3 frame is ignored,
    // so a forged CRC32c-only marker can no longer reclassify a tampered HMAC
    // window as PASS.
    let trusted_pubkey = segments
        .first()
        .and_then(|s| s.parent())
        .map(|dir| dir.join("signing.key"))
        .and_then(|p| crate::wal::signing::load_signing_pubkey_if_present(&p));
    let mut out = Vec::new();
    for seg in segments {
        let ranges = extract_redaction_authorisations(seg, trusted_pubkey.as_deref())?;
        out.extend(ranges);
    }
    Ok(out)
}

/// Walk every segment, extract `COMPACTION_MARKER` frames, verify each
/// against the HMAC key, and reclassify mismatches that overlap an
/// authorised redaction window. Returns aggregated counts + failure
/// strings for the renderer. Pure — no IO except the segment reads
/// already performed by `extract_markers`.
fn verify_segments(
    segments: &[PathBuf],
    key: &[u8],
    authorised: &[AuthorisedRange],
) -> Result<VerifyOutcome> {
    let mut outcome = VerifyOutcome {
        total_markers: 0,
        total_verified: 0,
        failures: Vec::new(),
        reclassified: 0,
        authorised_count: authorised.len(),
    };
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    for seg in segments {
        let raw = std::fs::read(seg).with_context(|| format!("read segment {}", seg.display()))?;
        // A sub-header stub (fresh/empty segment) carries no markers — skip it as
        // before. Anything larger MUST reconstruct: a compressed (v2) segment whose
        // zstd blob won't decompress is tamper-SUSPECT — surface it as a failure
        // rather than the old silent "0 markers, clean" (which made `verify` a
        // no-op on every compressed segment).
        if raw.len() < SEGMENT_HEADER_LEN {
            continue;
        }
        // GR-007 — a segment large enough to carry a header (≥ SEGMENT_HEADER_LEN)
        // whose header does NOT parse is tamper-suspect. `logical_segment_bytes`
        // silently falls back to treating it as a header-less bare frame stream
        // (offset 0), which would find 0 markers and report the segment "clean" —
        // a verify FAIL-OPEN for a corrupted-header (especially compressed)
        // segment. Production segments always carry a parseable v1/v2 header, so
        // surface the parse failure as a verification failure instead of silently
        // passing it as a header-less stream.
        if crate::wal::segment_header::parse_segment_header(&raw).is_err() {
            outcome.failures.push(format!(
                "{}: segment header does not parse — tamper-suspect (a corrupted \
                 header would otherwise be read as a header-less stream, hiding its \
                 markers)",
                seg.display()
            ));
            continue;
        }
        let (header_len, logical) = match compaction::logical_segment_bytes(&raw) {
            Ok(v) => v,
            Err(e) => {
                outcome.failures.push(format!("{}: unreconstructable segment: {e}", seg.display()));
                continue;
            }
        };
        let markers = extract_markers_from(&logical, header_len);
        for m in &markers {
            outcome.total_markers += 1;
            match compaction::verify_marker_bytes(&logical, key, m) {
                Ok(()) => outcome.total_verified += 1,
                Err(e) => {
                    if window_overlaps_authorised(seg, m.from_offset, m.to_offset, authorised) {
                        // HMAC mismatch is expected — the operator
                        // authorised the byte change via 0xF3. Count
                        // as verified but record the reclassification
                        // for the operator-facing summary.
                        outcome.total_verified += 1;
                        outcome.reclassified += 1;
                    } else {
                        outcome.failures.push(format!(
                            "{} window {}-{}: {e}",
                            seg.display(),
                            m.from_offset,
                            m.to_offset
                        ));
                    }
                }
            }
        }
    }
    Ok(outcome)
}

/// Render the verify outcome to stdout in either JSON envelope or the
/// operator-friendly table form. Side-effect only — no return value.
fn render_verify_outcome(segments: &[PathBuf], outcome: &VerifyOutcome, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "segments": segments.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "markers_total": outcome.total_markers,
                    "markers_ok": outcome.total_verified,
                    "operator_authorised_redactions": outcome.reclassified,
                    "authorised_redaction_count": outcome.authorised_count,
                    "failures": outcome.failures,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "# verified {}/{} marker(s) across {} segment(s)",
                outcome.total_verified,
                outcome.total_markers,
                segments.len()
            );
            if outcome.reclassified > 0 {
                println!(
                    "  + {} HMAC mismatch(es) reclassified as \
                     operator-authorised via REDACTION_MARKER (0xF3)",
                    outcome.reclassified
                );
            }
            if outcome.authorised_count > 0 {
                println!(
                    "  {} authorised redaction range(s) recorded in WAL audit log",
                    outcome.authorised_count
                );
            }
            for f in &outcome.failures {
                println!("  FAIL  {f}");
            }
            if outcome.total_markers == 0 {
                println!(
                    "(no compaction markers yet — daemon emits them every {} frames or {} MiB)",
                    compaction::MAX_FRAMES_BETWEEN_MARKERS,
                    compaction::MAX_BYTES_BETWEEN_MARKERS / (1024 * 1024),
                );
            }
        }
    }
}

/// SC-09 — drop every segment BEFORE the last one carrying a
/// `0xD9 HMAC_KEY_ROTATED` frame (those markers were signed with a since-
/// replaced key). Returns the original list unchanged (with an operator note)
/// when no rotation has been recorded. Boundary is segment-granular: a marker
/// written before the rotation frame WITHIN the rotation segment is still
/// verified — today's `rewrap-hmac-key` restores the SAME key bytes so every
/// marker verifies regardless; a future `rotate-hmac-key` (new key value) would
/// want frame-granular precision, tracked as a follow-on.
fn apply_since_rotation_filter(segments: Vec<PathBuf>, output: OutputFormat) -> Vec<PathBuf> {
    // The rotation boundary is only trusted when its 0xD9 frame is SIGNED by the
    // operator's OWN key (read from <wal_dir>/signing.key). `None` (no key on
    // disk) ⇒ no boundary ⇒ the FULL history is verified (fail safe — a forged
    // 0xD9 can no longer make `--since-rotation` skip genuine history).
    let trusted_pubkey = segments
        .first()
        .and_then(|s| s.parent())
        .map(|dir| dir.join("signing.key"))
        .and_then(|p| crate::wal::signing::load_signing_pubkey_if_present(&p));
    match find_last_rotation_segment(&segments, trusted_pubkey.as_deref()) {
        Some(idx) => {
            let skipped = idx;
            if !matches!(output, OutputFormat::Json | OutputFormat::Jsonl) && skipped > 0 {
                println!(
                    "# --since-rotation: skipping {skipped} pre-rotation segment(s); \
                     verifying from {}",
                    segments[idx].display()
                );
            }
            segments.into_iter().skip(idx).collect()
        }
        None => {
            if !matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                println!(
                    "# --since-rotation: no HMAC_KEY_ROTATED (0xD9) frame found — \
                     verifying the full history"
                );
            }
            segments
        }
    }
}

/// Index (in the sorted `segments`) of the LAST segment containing a
/// `0xD9 HMAC_KEY_ROTATED` frame, or `None` if no segment has one.
fn find_last_rotation_segment(segments: &[PathBuf], trusted_pubkey: Option<&str>) -> Option<usize> {
    segments
        .iter()
        .enumerate()
        .filter(|(_, seg)| segment_has_rotation(seg, trusted_pubkey))
        .map(|(i, _)| i)
        .next_back()
}

/// Does this segment contain at least one OPERATOR-SIGNED `0xD9 HMAC_KEY_ROTATED`
/// frame? Tolerant — a torn tail / unreadable file just yields `false`. A 0xD9
/// frame whose signature does NOT verify against the operator's own key
/// (`trusted_pubkey`) is IGNORED — that is the forged-rotation bypass closure.
fn segment_has_rotation(seg: &Path, trusted_pubkey: Option<&str>) -> bool {
    use crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED;
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;

    // No operator key on disk ⇒ no rotation boundary can be authenticated ⇒ none.
    let Some(trusted_pubkey) = trusted_pubkey else {
        return false;
    };
    let Ok(raw) = std::fs::read(seg) else {
        return false;
    };
    if raw.len() < SEGMENT_HEADER_LEN {
        return false;
    }
    // Decompress-aware: a 0xD9 rotation frame inside a compressed (v2) segment's
    // zstd blob must still anchor the `--since-rotation` boundary.
    let Ok((header_len, bytes)) = compaction::logical_segment_bytes(&raw) else {
        return false;
    };
    let mut cursor = header_len;
    while cursor < bytes.len() {
        let Ok(dec) = decode_frame(&bytes[cursor..]) else {
            break;
        };
        if dec.header.event_type == EVENT_TYPE_HMAC_KEY_ROTATED {
            // AUTHENTICATE before trusting it as a boundary — a forged CRC32c-only
            // 0xD9 has no valid operator signature ⇒ NOT a rotation point.
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(dec.payload) {
                let new_key_sha256 = payload["new_key_sha256"].as_str().unwrap_or("");
                let replaced = payload["replaced"].as_bool().unwrap_or(false);
                let reason = payload["reason"].as_str().unwrap_or("");
                let ts_unix = payload["ts_unix"].as_i64().unwrap_or(0);
                let sig = payload["sig"].as_str().unwrap_or("");
                let msg = crate::cli::security::rotation_authorisation_message(
                    new_key_sha256,
                    replaced,
                    reason,
                    ts_unix,
                );
                if crate::wal::signing::verify_b64(trusted_pubkey, sig, &msg).is_ok() {
                    return true;
                }
            }
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor += total;
    }
    false
}

/// Enumerate `*.wal` segments under `dir`, sorted by sequence number.
///
/// GR-07 (Session 27): the segment writer pins `{:06}.wal` zero-
/// padded filenames at the single emit site
/// [`crate::wal::writer`] (`format!("{:06}.wal", next_seq)`) plus
/// [`crate::cli::wal`] (`format!("{:06}.wal", seq)`). With that
/// invariant lexicographic sort == numeric sort for sequences
/// 0..=999_999 (which is ~125 GB at the 128 MB segment cap — i.e.
/// well past any realistic operator lifetime). A future writer
/// that drops the padding would silently re-order this list; the
/// `is_zero_padded_segment_name` drift test in `wal::writer` tests
/// pins the format contract.
fn list_segments(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("read wal dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("wal") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// One operator-authorised redaction range extracted from a 0xF3
/// marker. Used by the verifier to reclassify HMAC mismatches that
/// fall inside a known-authorised range as PASS-with-note instead of
/// FAIL. The segment string matches the WAL frame payload verbatim —
/// `Path::display()` of the segment that was redacted.
#[derive(Debug, Clone)]
struct AuthorisedRange {
    pub segment: String,
    pub offsets: Vec<u64>,
}

/// Walk a WAL segment and collect every `REDACTION_MARKER` (0xF3)
/// frame's `{segment, redacted_offsets}` into an authorisation record.
/// Marker frames live in dedicated `memory-redact-*.wal` segments
/// emitted by `cli/memory.rs::run_physical_redaction`; the segment
/// being verified is NOT the same file as the segment named INSIDE
/// the marker (that's the segment whose bytes were rewritten).
fn extract_redaction_authorisations(
    seg: &Path,
    trusted_pubkey: Option<&str>,
) -> Result<Vec<AuthorisedRange>> {
    use crate::wal::events::EVENT_TYPE_REDACTION_MARKER;
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;

    // No operator key on disk ⇒ no redaction exemption can be authenticated ⇒
    // trust NONE (fail closed against forged 0xF3 frames).
    let Some(trusted_pubkey) = trusted_pubkey else {
        return Ok(Vec::new());
    };
    let raw = std::fs::read(seg).with_context(|| format!("read segment {}", seg.display()))?;
    if raw.len() < SEGMENT_HEADER_LEN {
        return Ok(Vec::new());
    }
    // Decompress-aware: a 0xF3 redaction marker inside a compressed (v2)
    // segment's zstd blob must still be found, else an operator-authorised
    // redaction would surface as a bogus verify FAILURE.
    let (header_len, bytes) = match compaction::logical_segment_bytes(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    let mut cursor = header_len;
    let mut out = Vec::new();
    while cursor < bytes.len() {
        let slice = &bytes[cursor..];
        let dec = match decode_frame(slice) {
            Ok(d) => d,
            Err(_) => break,
        };
        let total = dec.header.total_len as usize;
        if dec.header.event_type == EVENT_TYPE_REDACTION_MARKER {
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(dec.payload) {
                let segment = payload["segment"].as_str().unwrap_or("").to_string();
                let offsets: Vec<u64> = payload["redacted_offsets"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                    .unwrap_or_default();
                let bytes_redacted = payload["bytes_redacted"].as_u64().unwrap_or(0);
                let topic = payload["topic"].as_str().unwrap_or("");
                let ts_unix = payload["ts_unix"].as_i64().unwrap_or(0);
                let sig = payload["sig"].as_str().unwrap_or("");
                // AUTHENTICATE: the marker's signature MUST verify against the
                // OPERATOR's own key over the canonical authorisation. A forged
                // CRC32c-only frame has no valid signature ⇒ ignored. We verify
                // against the trusted ON-DISK key, NEVER the payload's
                // `signer_pubkey` (an attacker would set that to their own key).
                let msg = crate::wal::redact::redaction_authorisation_message(
                    &segment,
                    &offsets,
                    bytes_redacted,
                    topic,
                    ts_unix,
                );
                let authentic = crate::wal::signing::verify_b64(trusted_pubkey, sig, &msg).is_ok();
                if authentic && !segment.is_empty() && !offsets.is_empty() {
                    out.push(AuthorisedRange { segment, offsets });
                }
            }
        }
        if total == 0 {
            break;
        }
        cursor += total;
    }
    Ok(out)
}

/// Does the COMPACTION_MARKER's window `[from, to]` overlap any
/// authorised-redaction offset on this segment? Matches the segment
/// by `Path::display().to_string()` so the comparison agrees with the
/// payload encoding `cli/memory.rs::run_physical_redaction` used when
/// writing the marker.
fn window_overlaps_authorised(
    seg: &Path,
    from_offset: u64,
    to_offset: u64,
    authorised: &[AuthorisedRange],
) -> bool {
    // Reviewer-2 P0-B fix (2026-05-20): compare segments by file_name()
    // not full display(). Both writer and reader can reach a segment
    // via different path forms (relative vs absolute, symlinks, OS
    // separator drift) — using filename as identity makes the match
    // path-invariant. Backward-compatibility: legacy markers may carry
    // a full path string; normalise both sides through file_name() so
    // old + new payloads converge on the same identity.
    let seg_name = match seg.file_name().map(|n| n.to_string_lossy().into_owned()) {
        Some(n) => n,
        None => return false,
    };
    for r in authorised {
        let range_name = Path::new(&r.segment)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| r.segment.clone());
        if range_name != seg_name {
            continue;
        }
        if r.offsets
            .iter()
            .any(|o| *o >= from_offset && *o < to_offset)
        {
            return true;
        }
    }
    false
}

/// Walk a LOGICAL segment byte slice (post-decompression — see
/// [`compaction::logical_segment_bytes`]) from after its `header_len`, decoding
/// frames in order, and pull out every COMPACTION_MARKER payload. Tolerates
/// trailing partial frames (interrupted-writer crashes) by stopping at the first
/// decode error.
fn extract_markers_from(logical: &[u8], header_len: usize) -> Vec<compaction::MarkerPayload> {
    use crate::wal::events::EVENT_TYPE_COMPACTION_MARKER;
    use crate::wal::frame::decode_frame;

    let mut out = Vec::new();
    if logical.len() <= header_len {
        return out;
    }
    let mut cursor = header_len;
    while cursor < logical.len() {
        let dec = match decode_frame(&logical[cursor..]) {
            Ok(d) => d,
            Err(_) => break, // partial trailing frame — stop walking
        };
        let total = dec.header.total_len as usize;
        if dec.header.event_type == EVENT_TYPE_COMPACTION_MARKER {
            if let Ok(payload) = serde_json::from_slice::<compaction::MarkerPayload>(dec.payload) {
                out.push(payload);
            }
        }
        if total == 0 {
            break;
        }
        cursor += total;
    }
    out
}

/// Path-based convenience over [`extract_markers_from`]: reads the segment,
/// reconstructs its LOGICAL bytes (decompressing a compressed v2 segment so the
/// marker frames inside the zstd blob are actually walked), and extracts the
/// markers. Tolerant: a too-short / unparseable file yields none.
fn extract_markers(seg: &Path) -> Result<Vec<compaction::MarkerPayload>> {
    let raw = std::fs::read(seg).with_context(|| format!("read segment {}", seg.display()))?;
    let Ok((header_len, logical)) = compaction::logical_segment_bytes(&raw) else {
        return Ok(Vec::new());
    };
    Ok(extract_markers_from(&logical, header_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_segments_returns_empty_for_missing_dir() {
        let r = list_segments(std::path::Path::new(
            "/definitely/not/a/real/wal/dir/anywhere",
        ))
        .unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn list_segments_picks_up_wal_files_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("000003.wal"), b"x").unwrap();
        std::fs::write(dir.path().join("000001.wal"), b"x").unwrap();
        std::fs::write(dir.path().join("000002.wal"), b"x").unwrap();
        std::fs::write(dir.path().join("ignore.txt"), b"x").unwrap();
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 3);
        assert!(segs[0].to_string_lossy().contains("000001"));
        assert!(segs[1].to_string_lossy().contains("000002"));
        assert!(segs[2].to_string_lossy().contains("000003"));
    }

    #[test]
    fn extract_markers_returns_empty_for_too_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        std::fs::write(&seg, b"too short").unwrap();
        let markers = extract_markers(&seg).unwrap();
        assert!(markers.is_empty());
    }

    // ── SC-09-B: --since-rotation boundary ──────────────────────────────────

    async fn write_event_seg(seg: std::path::PathBuf, event_type: u8) {
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let payload = b"{}".to_vec();
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.ok();
    }

    /// Write a segment with an OPERATOR-SIGNED 0xD9 rotation frame (the signing
    /// key lives in `dir`, the same place verify reads its trust root from).
    async fn write_signed_rotation_seg(dir: &std::path::Path, seg: std::path::PathBuf) {
        use crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED;
        let key = crate::wal::signing::load_or_init_signing_key(&dir.join("signing.key")).unwrap();
        let msg =
            crate::cli::security::rotation_authorisation_message("abc123", true, "rewrap", 1700);
        let payload = serde_json::to_vec(&serde_json::json!({
            "new_key_sha256": "abc123",
            "replaced": true,
            "reason": "rewrap",
            "ts_unix": 1700,
            "signer_pubkey": crate::wal::signing::pubkey_b64(&key),
            "sig": crate::wal::signing::sign_b64(&key, &msg),
        }))
        .unwrap();
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_HMAC_KEY_ROTATED, &payload).build();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.ok();
    }

    fn trusted_for(dir: &std::path::Path) -> Option<String> {
        crate::wal::signing::load_signing_pubkey_if_present(&dir.join("signing.key"))
    }

    #[tokio::test]
    async fn since_rotation_finds_last_rotation_segment_and_filters() {
        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dir = tempfile::tempdir().unwrap();
        write_event_seg(dir.path().join("000001.wal"), EVENT_TYPE_RAW_TEXT).await;
        write_signed_rotation_seg(dir.path(), dir.path().join("000002.wal")).await;
        write_event_seg(dir.path().join("000003.wal"), EVENT_TYPE_RAW_TEXT).await;
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(
            find_last_rotation_segment(&segs, trusted_for(dir.path()).as_deref()),
            Some(1)
        );
        // The filter loads the trust root from the wal dir internally + keeps the
        // rotation segment + everything after it.
        let filtered = apply_since_rotation_filter(segs, OutputFormat::Json);
        assert_eq!(filtered.len(), 2);
        assert!(filtered[0].to_string_lossy().contains("000002"));
    }

    #[tokio::test]
    async fn since_rotation_last_wins_with_two_rotations() {
        let dir = tempfile::tempdir().unwrap();
        write_signed_rotation_seg(dir.path(), dir.path().join("000001.wal")).await;
        write_signed_rotation_seg(dir.path(), dir.path().join("000002.wal")).await;
        let segs = list_segments(dir.path()).unwrap();
        // The MOST RECENT rotation is the boundary.
        assert_eq!(
            find_last_rotation_segment(&segs, trusted_for(dir.path()).as_deref()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn since_rotation_ignores_a_forged_unsigned_rotation_frame() {
        // The 0xD9 bypass closure: a CRC32c-valid but UNSIGNED 0xD9 (an attacker
        // can write but not sign it) must NOT be treated as a boundary — else
        // `--since-rotation` would skip the genuine history. A real signed
        // rotation sits at 000001; the forged one at 000002 is ignored, so the
        // boundary is index 0, NOT 1.
        use crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED;
        let dir = tempfile::tempdir().unwrap();
        write_signed_rotation_seg(dir.path(), dir.path().join("000001.wal")).await;
        write_event_seg(dir.path().join("000002.wal"), EVENT_TYPE_HMAC_KEY_ROTATED).await;
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(
            find_last_rotation_segment(&segs, trusted_for(dir.path()).as_deref()),
            Some(0),
            "a forged unsigned 0xD9 must be ignored",
        );
    }

    #[tokio::test]
    async fn since_rotation_none_verifies_full_history() {
        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dir = tempfile::tempdir().unwrap();
        write_event_seg(dir.path().join("000001.wal"), EVENT_TYPE_RAW_TEXT).await;
        write_event_seg(dir.path().join("000002.wal"), EVENT_TYPE_RAW_TEXT).await;
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(find_last_rotation_segment(&segs, None), None);
        // No rotation → the full list is returned unchanged.
        let n = segs.len();
        assert_eq!(apply_since_rotation_filter(segs, OutputFormat::Json).len(), n);
    }

    #[test]
    fn segment_has_rotation_false_for_short_or_missing() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        std::fs::write(&seg, b"short").unwrap();
        assert!(!segment_has_rotation(&seg, Some("anything")));
        assert!(!segment_has_rotation(&dir.path().join("does-not-exist.wal"), Some("anything")));
    }

    // V02-03 acceptance (note 2026-05-16): the end-to-end "tamper
    // a real WAL segment, run verify, assert non-zero exit" path
    // is intentionally layered across three existing tests rather
    // than reproduced as a single integration:
    //   1. `wal::compaction::tests::verify_marker_detects_tamper` —
    //      pins the HMAC primitive's tamper detection.
    //   2. `wal::compaction::tests::verify_marker_succeeds_on_matching_bytes`
    //      — pins the positive path (no false-positive).
    //   3. `run_verify` itself bails with `anyhow::bail!("{n} marker(s)
    //      failed verification")` at line 145 when `failures` is
    //      non-empty, so any non-zero failure count surfaces as a
    //      non-zero CLI exit. The bail path is exercised every time
    //      either of the unit tests above fails locally during a
    //      writer change.
    // A monolithic end-to-end test that drives the writer + marker
    // emit + tamper + verify cycle gets tangled with the writer's
    // segment-reopen semantics (the 60-byte segment header doesn't
    // get re-emitted on reopen) without adding signal beyond the
    // layered coverage above. If the layered tests start passing
    // while the daemon actually misbehaves, that's the gap to close;
    // until then the existing tests pin the V02-03 acceptance.

    #[tokio::test]
    async fn extract_redaction_authorisations_finds_emitted_marker() {
        use crate::wal::redact::emit_redaction_marker;
        use crate::wal::writer::spawn;

        let dir = tempfile::tempdir().unwrap();
        let audit_seg = dir.path().join("memory-redact-1.wal");
        let (writer, join) = spawn(audit_seg.clone()).unwrap();
        // Target segment lives in the SAME wal dir as the marker writer + the
        // signing key (mirrors production: redacted segment, marker, and key all
        // under ~/.neoth/wal).
        let target = dir.path().join("000001.wal");
        let offsets = vec![100u64, 250u64];
        emit_redaction_marker(&writer, &target, &offsets, 32, "Acme", "cli", 1700)
            .await
            .unwrap();
        drop(writer);
        let _ = join.await;

        // Load the trust root the same way `collect_authorised_ranges` does.
        let trusted =
            crate::wal::signing::load_signing_pubkey_if_present(&dir.path().join("signing.key"));
        assert!(trusted.is_some(), "emit must have created the operator signing key");
        let ranges = extract_redaction_authorisations(&audit_seg, trusted.as_deref()).unwrap();
        assert_eq!(ranges.len(), 1, "an operator-signed marker must be honoured");
        assert!(ranges[0].segment.ends_with("000001.wal"));
        assert_eq!(ranges[0].offsets, offsets);

        // The 0xF3 bypass closure: an exemption NOT signed by the operator key is
        // IGNORED. No trust root ⇒ nothing honoured; a different key ⇒ rejected.
        assert!(
            extract_redaction_authorisations(&audit_seg, None).unwrap().is_empty(),
            "no trust root ⇒ no exemption honoured",
        );
        let wrong_key =
            crate::wal::signing::pubkey_b64(&ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]));
        assert!(
            extract_redaction_authorisations(&audit_seg, Some(&wrong_key))
                .unwrap()
                .is_empty(),
            "a marker signed by a DIFFERENT key must not be honoured",
        );
    }

    #[test]
    fn window_overlaps_authorised_matches_segment_and_offset_range() {
        // Authorised offset at 200 inside window [100..300] → overlap.
        let r = AuthorisedRange {
            segment: "/wal/seg.wal".into(),
            offsets: vec![200],
        };
        let p = std::path::Path::new("/wal/seg.wal");
        assert!(window_overlaps_authorised(p, 100, 300, &[r]));
    }

    #[test]
    fn window_overlaps_authorised_misses_when_offset_outside_window() {
        let r = AuthorisedRange {
            segment: "/wal/seg.wal".into(),
            offsets: vec![50],
        };
        let p = std::path::Path::new("/wal/seg.wal");
        // Offset 50 is BEFORE the window start 100.
        assert!(!window_overlaps_authorised(p, 100, 300, &[r]));
    }

    #[test]
    fn window_overlaps_authorised_misses_when_segment_differs() {
        // Same offset would match — but different segment string.
        let r = AuthorisedRange {
            segment: "/wal/other.wal".into(),
            offsets: vec![200],
        };
        let p = std::path::Path::new("/wal/seg.wal");
        assert!(!window_overlaps_authorised(p, 100, 300, &[r]));
    }

    #[test]
    fn window_overlaps_authorised_relative_vs_absolute_path_match() {
        // Reviewer-2 P0-B regression guard (2026-05-20): the marker
        // payload contains a bare filename ("000001.wal"); the verifier
        // walks segments via `--wal-dir` that may resolve to a relative
        // OR absolute path. Both must match the same authorised entry,
        // otherwise authorised redactions surface as bogus FAILs.
        let absolute = AuthorisedRange {
            segment: "/var/lib/neoth/wal/000001.wal".into(),
            offsets: vec![200],
        };
        // Verifier passes a relative-style path.
        let relative = std::path::Path::new("./wal/000001.wal");
        assert!(
            window_overlaps_authorised(relative, 100, 300, &[absolute]),
            "absolute-in-marker + relative-in-verifier MUST match via filename"
        );

        // Also: marker carrying only the bare filename (new format)
        // matches any path that ends with that filename.
        let bare = AuthorisedRange {
            segment: "000001.wal".into(),
            offsets: vec![200],
        };
        let any_full = std::path::Path::new("/some/other/dir/000001.wal");
        assert!(
            window_overlaps_authorised(any_full, 100, 300, &[bare]),
            "bare-filename-in-marker MUST match any path ending with that filename"
        );
    }

    #[test]
    fn window_overlaps_authorised_to_offset_is_exclusive() {
        // Offset exactly == to_offset → NOT in window (half-open).
        let r = AuthorisedRange {
            segment: "/wal/seg.wal".into(),
            offsets: vec![300],
        };
        let p = std::path::Path::new("/wal/seg.wal");
        assert!(!window_overlaps_authorised(p, 100, 300, &[r]));
        // Offset == from_offset → IN window.
        let r2 = AuthorisedRange {
            segment: "/wal/seg.wal".into(),
            offsets: vec![100],
        };
        assert!(window_overlaps_authorised(p, 100, 300, &[r2]));
    }

    /// Append a fully-formed `0xF3 REDACTION_MARKER` frame, signed by `key`, into
    /// a fresh audit segment in `wal_dir`. Models an attacker who can WRITE a WAL
    /// frame + sign it with THEIR OWN key — the exact shape `run_verify` must
    /// refuse unless `key` is the operator's trusted signing key.
    async fn write_signed_redaction_frame(
        wal_dir: &Path,
        audit_name: &str,
        target_segment: &str,
        offsets: &[u64],
        bytes_redacted: u64,
        topic: &str,
        ts_unix: i64,
        key: &ed25519_dalek::SigningKey,
    ) {
        let msg = crate::wal::redact::redaction_authorisation_message(
            target_segment,
            offsets,
            bytes_redacted,
            topic,
            ts_unix,
        );
        let payload = serde_json::to_vec(&serde_json::json!({
            "segment": target_segment,
            "redacted_offsets": offsets,
            "bytes_redacted": bytes_redacted,
            "topic": topic,
            "source": "attacker",
            "ts_unix": ts_unix,
            "signer_pubkey": crate::wal::signing::pubkey_b64(key),
            "sig": crate::wal::signing::sign_b64(key, &msg),
        }))
        .unwrap();
        let (w, j) = crate::wal::writer::spawn(wal_dir.join(audit_name)).unwrap();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_REDACTION_MARKER, &payload)
                .build();
        w.append(header, payload).await.unwrap();
        drop(w);
        let _ = j.await;
    }

    /// AP-08 — end-to-end `run_verify` over the `0xF3` redaction-exemption path:
    /// the public-CLI-entry counterpart to the function-level
    /// `extract_redaction_authorisations` test. Proves at the `run_verify` seam
    /// (not just the extracted helper) that the Session-39 signature closure holds:
    /// a clean WAL passes; a tampered HMAC window FAILS; an ATTACKER-signed `0xF3`
    /// does NOT authorise it (the bypass that was open); and only the OPERATOR-
    /// signed `0xF3` reclassifies it to PASS.
    #[tokio::test]
    async fn run_verify_e2e_redaction_exemption_signature_trust() {
        use crate::wal::compaction::{load_or_init_key, CompactionState};
        use crate::wal::events::{EVENT_TYPE_COMPACTION_MARKER, EVENT_TYPE_RAW_TEXT};
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{SegmentHeader, SEGMENT_HEADER_LEN};

        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path();
        let seg = wal_dir.join("000001.wal");
        let key_path = wal_dir.join("hmac.key");
        let key = load_or_init_key(&key_path).unwrap();

        // The operator's ed25519 signing key must exist BEFORE the attacker step,
        // so the trust root is the operator key (not "no key") — that lets the test
        // prove key-MISMATCH rejection, not merely the fail-closed no-key path.
        let signing_key_path = wal_dir.join("signing.key");
        crate::wal::signing::load_or_init_signing_key(&signing_key_path).unwrap();

        // 1+2. Build the verified segment FULLY MANUALLY — SEGMENT_HEADER + 3 data
        //      frames + the COMPACTION_MARKER over them, every frame via the same
        //      `encode_frame` the walker decodes. (A mixed writer-frames +
        //      manual-marker-append segment hits the writer-reopen tangle the
        //      module note at the top of `tests` warns about; a single-encoder
        //      build sidesteps it entirely.) `tamper` flips a byte INSIDE the
        //      marker window AFTER the HMAC is computed → an authorisation-or-fail.
        // 1+2. Build the verified segment manually — SEGMENT_HEADER + 3 data
        //      frames + a COMPACTION_MARKER (0xF0) over them, every frame via the
        //      same `encode_frame` the walker decodes. (A mixed writer-frames +
        //      manual-append segment hits the writer-reopen tangle the module note
        //      atop `tests` warns about; a single-encoder build sidesteps it.)
        let from = SEGMENT_HEADER_LEN as u64;
        let mut seg_bytes = SegmentHeader::new(1, 1, 0, 0, [0u8; 16]).to_le_bytes().to_vec();
        for p in [b"alpha".as_slice(), b"beta", b"gamma"] {
            let h = crate::wal::HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, p).build();
            seg_bytes.extend_from_slice(&encode_frame(&h, p));
        }
        let to = seg_bytes.len() as u64;
        let mut state = CompactionState::new(&key, from);
        state.update(&seg_bytes[from as usize..]);
        let marker = state.finalise_marker(&key, to);
        let mpayload = serde_json::to_vec(&marker).unwrap();
        let mh = crate::wal::HeaderBuilder::new(EVENT_TYPE_COMPACTION_MARKER, &mpayload).build();
        seg_bytes.extend_from_slice(&encode_frame(&mh, &mpayload));
        std::fs::write(&seg, &seg_bytes).unwrap();

        let args = || VerifyArgs {
            wal_dir: Some(wal_dir.to_path_buf()),
            key: Some(key_path.clone()),
            segment: None,
            since_rotation: false,
            output: OutputFormat::Json,
        };

        // 2a. Intact window → PASS.
        run_verify(args())
            .await
            .expect("an intact marker window verifies clean");

        // 3. Redact frame 1 with the REAL `redact_frame_in_place` primitive (zeros
        //    payload + sets REDACTED + recomputes the frame CRC so the segment stays
        //    walkable + the 0xF0 marker reachable) → the marker's pre-redaction HMAC
        //    now mismatches. With NO authorisation, run_verify FAILS.
        {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&seg)
                .unwrap();
            let h1 = crate::wal::HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, b"alpha".as_slice()).build();
            crate::wal::redact::redact_frame_in_place(&mut f, from, &h1).unwrap();
            f.sync_all().unwrap();
        }
        assert!(
            run_verify(args()).await.is_err(),
            "a redacted (HMAC-mismatched) window with no authorisation must FAIL",
        );

        // 4. ATTACKER-signed 0xF3 over the redacted frame offset → NOT the operator
        //    key → must NOT authorise → still FAILS (the bypass closure). The 0xF3
        //    offset is the FRAME-START offset (= `from`), matching what the real
        //    `scan_and_redact` records in `frames_redacted`.
        let redacted_offset = from;
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        write_signed_redaction_frame(
            wal_dir,
            "attacker-audit.wal",
            "000001.wal",
            &[redacted_offset],
            1,
            "e2e",
            1700,
            &attacker,
        )
        .await;
        assert!(
            run_verify(args()).await.is_err(),
            "a 0xF3 signed by a NON-operator key must NOT authorise the window",
        );

        // 5. OPERATOR-signed 0xF3 (real emit, signs with <wal_dir>/signing.key) →
        //    honoured → the window reclassifies to PASS.
        let (rw, rj) = crate::wal::writer::spawn(wal_dir.join("redact-audit.wal")).unwrap();
        crate::wal::redact::emit_redaction_marker(
            &rw,
            &seg,
            &[redacted_offset],
            1,
            "e2e",
            "operator",
            1700,
        )
        .await
        .unwrap();
        drop(rw);
        let _ = rj.await;
        run_verify(args())
            .await
            .expect("an operator-signed 0xF3 over the tampered window reclassifies to PASS");
    }

    /// Compression-verify gap closure: `run_verify` must FIND + verify a
    /// COMPACTION_MARKER inside a COMPRESSED (v2) segment's zstd blob. Before the
    /// fix, `extract_markers` walked raw compressed bytes → 0 markers → a silent
    /// "clean" verdict that checked NOTHING. Now it decompresses first.
    #[tokio::test]
    async fn run_verify_finds_and_checks_markers_in_a_compressed_segment() {
        use crate::wal::HeaderBuilder;
        use crate::wal::compaction::{load_or_init_key, CompactionState};
        use crate::wal::compress::compress_frames;
        use crate::wal::events::{EVENT_TYPE_COMPACTION_MARKER, EVENT_TYPE_RAW_TEXT};
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{
            SegmentHeaderV2, SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN,
        };

        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path();
        let seg = wal_dir.join("000001.wal");
        let key_path = wal_dir.join("hmac.key");
        let key = load_or_init_key(&key_path).unwrap();
        let from = SEGMENT_HEADER_V2_LEN as u64;

        // 3 data frames + a COMPACTION_MARKER over them, then compress the lot.
        let mut data = Vec::new();
        for p in [b"alpha".as_slice(), b"bravo", b"charlie"] {
            let h = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, p).build();
            data.extend_from_slice(&encode_frame(&h, p));
        }
        let to = from + data.len() as u64;
        let mut state = CompactionState::new(&key, from);
        state.update(&data);
        let marker = state.finalise_marker(&key, to);
        let mpayload = serde_json::to_vec(&marker).unwrap();
        let mh = HeaderBuilder::new(EVENT_TYPE_COMPACTION_MARKER, &mpayload).build();
        data.extend_from_slice(&encode_frame(&mh, &mpayload));

        let blob = compress_frames(&data).unwrap();
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut file = hdr.to_le_bytes().to_vec();
        file.extend_from_slice(&blob);
        std::fs::write(&seg, file).unwrap();

        // The walk now decompresses → the marker inside the blob IS found.
        let markers = extract_markers(&seg).unwrap();
        assert_eq!(markers.len(), 1, "marker inside the compressed blob must be found");

        // And `run_verify` checks it (clean) instead of reporting a hollow pass.
        let args = VerifyArgs {
            wal_dir: Some(wal_dir.to_path_buf()),
            key: Some(key_path.clone()),
            segment: None,
            since_rotation: false,
            output: OutputFormat::Json,
        };
        run_verify(args)
            .await
            .expect("a compressed segment with an intact marker verifies clean");
    }

    #[test]
    fn verify_flags_a_corrupt_header_segment_as_tamper_suspect() {
        // GR-007: a segment large enough to carry a header but whose header does
        // NOT parse must be reported as a verification FAILURE (tamper-suspect),
        // not silently treated as a header-less bare stream that finds 0 markers
        // and reports "clean" — that was the verify fail-open for a corrupted
        // (especially compressed) segment. FAILS pre-fix (0 failures), passes post.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        // ≥ header length of bytes that do NOT form a valid segment header.
        let n = crate::wal::segment_header::SEGMENT_HEADER_LEN + 40;
        std::fs::write(&seg, vec![0xFFu8; n]).unwrap();
        let outcome = verify_segments(std::slice::from_ref(&seg), b"any-key", &[]).unwrap();
        assert!(
            !outcome.failures.is_empty(),
            "a corrupt-header segment must be flagged as tamper-suspect, not silently clean"
        );
        assert!(
            outcome.failures[0].contains("header does not parse"),
            "the failure must name the unparseable header: {:?}",
            outcome.failures
        );
    }
}
