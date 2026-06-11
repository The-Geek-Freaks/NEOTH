//! Physical WAL payload redaction (C-15).
//!
//! When an operator runs `neoth memory forget --topic X --physical`,
//! the SQLite-tier wipe + TOMBSTONE_REQUESTED audit anchor are not
//! enough for a GDPR-grade "this data is gone" claim — the original
//! payload bytes still sit in the WAL segment files on disk. This
//! module closes that gap by:
//!
//!   1. Scanning every `.wal` segment for frames whose payload
//!      satisfies an operator-supplied predicate (typically: contains
//!      a topic substring after UTF-8 decode).
//!   2. For each matched frame: opening the segment with random-access
//!      I/O, overwriting the payload bytes with zeros, setting the
//!      `EventFlags::REDACTED` bit in the header, recomputing the CRC,
//!      and fsync'ing the segment.
//!
//! Invariants preserved post-redaction:
//!   - Frame size + offset layout: the redacted frame keeps its
//!     original `total_len` so segment offsets of subsequent frames
//!     are unchanged. Downstream readers (`indexer`, `cli/wal show`)
//!     still walk the segment correctly.
//!   - CRC: recomputed over `[magic + header + reserved + zeros +
//!     CRC slot]` so frame-integrity checks still pass.
//!   - `EventFlags::REDACTED` is set: decoders know to expect a
//!     mismatched `payload_hash` (the original hash stays in the
//!     header as the chain-of-evidence proof that THIS specific
//!     frame was once carrying the now-erased payload — without
//!     that, the audit trail would lose its anchor).
//!   - `event_type` + `event_id` + `hlc` + `session_id` + `node_id`
//!     are preserved — operators auditing the WAL still see "frame
//!     0x01 at this HLC was redacted at the operator's request".
//!
//! What is NOT preserved (by design):
//!   - The payload bytes themselves. Gone, overwritten with zeros.
//!   - The `payload_hash` field in the header is INTENTIONALLY left
//!     intact (see above) — this means automated integrity checkers
//!     MUST treat `payload_hash` as invalid when `REDACTED` is set.
//!
//! Companion to the CDX-01 TOMBSTONE_REQUESTED audit frame: that
//! frame records "operator wanted to forget topic X at time T"; this
//! module records "operator actually redacted those payload bytes
//! on disk". The pair gives a defensible audit story for the GDPR
//! right-to-erasure: intent + execution + invariant proof.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};

use super::header::{CRC_LEN, EventHeaderV2, HEADER_BODY_LEN, MAGIC, PREAMBLE_LEN};
use super::segment_header::{SEGMENT_HEADER_LEN, parse_segment_header};
use super::types::EventFlags;

/// Outcome of one redaction pass over one segment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactReport {
    /// Absolute frame offsets that were redacted (post-segment-header).
    pub frames_redacted: Vec<u64>,
    /// Total payload bytes overwritten with zeros.
    pub bytes_redacted: u64,
    /// Frames that already carried `EventFlags::REDACTED` — skipped
    /// (idempotent: re-running redaction on the same segment is safe).
    pub already_redacted: u32,
    /// Frames the predicate did NOT match — left untouched.
    pub frames_skipped: u32,
}

impl RedactReport {
    pub fn frames_redacted_count(&self) -> usize {
        self.frames_redacted.len()
    }
}

/// Walk every frame in `segment_path` and redact frames whose payload
/// satisfies `predicate(payload_bytes) -> bool`. Returns a report so
/// the caller (typically `memory::forget`) can emit a follow-up audit
/// event with the per-segment numbers.
///
/// `predicate` runs against the original payload bytes BEFORE they are
/// overwritten. Wrap it carefully: a panic in the predicate aborts the
/// scan; the partially-redacted segment stays consistent because each
/// redaction is fsync'd before the next predicate call.
pub fn scan_and_redact<F>(segment_path: &Path, mut predicate: F) -> Result<RedactReport>
where
    F: FnMut(&[u8]) -> bool,
{
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(segment_path)
        .with_context(|| format!("open WAL segment {}", segment_path.display()))?;

    let file_len = file
        .metadata()
        .with_context(|| format!("stat {}", segment_path.display()))?
        .len();

    // GOLD-ARCH-03: derive the start cursor from the real segment header
    // (v1 = 60 B, v2 = 61 B) instead of hardcoding SEGMENT_HEADER_LEN. With the
    // old hardcoded offset, a v2 segment's first frame was scanned one byte
    // early, the MAGIC check failed, the loop broke immediately, and redaction
    // SILENTLY scrubbed nothing — a privacy hole, since the caller
    // (`memory::forget`) reports success. We read the header from the bytes
    // already on disk.
    //
    // A *sealed* compressed segment (zstd blob body) cannot be redacted by
    // in-place seek+overwrite — the frames don't exist as raw bytes. A *live*
    // v2 segment carries the same COMPRESSED flag but a RAW body (compression
    // happens only at clean finalize), so the flag alone can't tell them
    // apart: we peek the body for a frame MAGIC. Raw frames ⇒ redact; a zstd
    // blob ⇒ refuse loudly rather than silently no-op (the caller,
    // `memory::forget`, reports success, so a silent skip is a privacy hole).
    // TODO(GOLD-ARCH-03b): decompress → redact → recompress → atomic-rewrite
    // path for finalised compressed segments.
    let header_len = {
        let probe_len = (SEGMENT_HEADER_LEN + 1).min(file_len as usize);
        let mut probe = vec![0u8; probe_len];
        file.seek(SeekFrom::Start(0)).context("seek to segment head")?;
        file.read_exact(&mut probe).context("read segment head")?;
        match parse_segment_header(&probe) {
            Ok(h) => {
                let hl = h.header_len() as u64;
                if h.is_compressed() && file_len > hl {
                    let mut magic = [0u8; PREAMBLE_LEN];
                    file.seek(SeekFrom::Start(hl)).context("seek to body")?;
                    if file.read_exact(&mut magic).is_ok() && magic != MAGIC {
                        anyhow::bail!(
                            "refusing to redact compressed WAL segment {} in place \
                             (sealed zstd body — see GOLD-ARCH-03b)",
                            segment_path.display()
                        );
                    }
                }
                hl
            }
            // GR-058: a segment large enough to carry a header whose header does
            // NOT parse is tamper-suspect. The old fallback guessed a v1 offset
            // (60); for a corrupt v2 header (61) — or any corruption — that
            // misaligned the very first frame so the MAGIC check broke
            // immediately and redaction SILENTLY scrubbed NOTHING. Because the
            // caller (`memory::forget --physical`) would then report success,
            // that is a privacy hole. Refuse loudly (like the sealed-compressed
            // case) so `forget` surfaces an error (GR-008) instead of a false
            // "erased" result. A file too small to even hold a header has no
            // frames to redact anyway → keep the benign no-op.
            Err(_) => {
                if file_len >= SEGMENT_HEADER_LEN as u64 {
                    anyhow::bail!(
                        "refusing to redact WAL segment {} — its header does not parse \
                         (tamper-suspect); a wrong-offset redaction would silently scrub nothing",
                        segment_path.display()
                    );
                }
                SEGMENT_HEADER_LEN as u64
            }
        }
    };
    let mut report = RedactReport::default();
    let mut cursor: u64 = header_len;

    while cursor + (PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN) as u64 <= file_len {
        // Read the preamble + header so we know the frame layout.
        file.seek(SeekFrom::Start(cursor))
            .context("seek to frame start")?;
        let mut head = [0u8; PREAMBLE_LEN + HEADER_BODY_LEN];
        file.read_exact(&mut head)
            .context("read frame preamble+header")?;
        if head[..PREAMBLE_LEN] != MAGIC {
            // Bad magic — segment is corrupted or we walked off the
            // end of a partially-written frame. Stop here rather than
            // risk redacting unrelated bytes downstream.
            break;
        }
        let header_bytes: &[u8; HEADER_BODY_LEN] =
            head[PREAMBLE_LEN..].try_into().expect("96 bytes");
        let header = EventHeaderV2::from_le_bytes(header_bytes)
            .with_context(|| format!("parse header at offset {cursor}"))?;
        let total_len = header.total_len as u64;
        if cursor + total_len > file_len {
            // Truncated frame — leave the segment as-is.
            break;
        }

        // Already redacted? Skip.
        if header.flags.contains(EventFlags::REDACTED) {
            report.already_redacted += 1;
            cursor += total_len;
            continue;
        }

        // Read the payload to feed the predicate.
        let payload_offset =
            cursor + (PREAMBLE_LEN + HEADER_BODY_LEN + header.reserved_len as usize) as u64;
        let payload_len = header.payload_len as usize;
        let mut payload = vec![0u8; payload_len];
        file.seek(SeekFrom::Start(payload_offset))
            .context("seek to payload")?;
        file.read_exact(&mut payload)
            .context("read payload for predicate")?;

        if !predicate(&payload) {
            report.frames_skipped += 1;
            cursor += total_len;
            continue;
        }

        // Match — perform the redaction.
        redact_frame_in_place(&mut file, cursor, &header).with_context(|| {
            format!(
                "redact frame at offset {cursor} in {}",
                segment_path.display()
            )
        })?;
        report.frames_redacted.push(cursor);
        report.bytes_redacted += payload_len as u64;
        cursor += total_len;
    }

    file.sync_all()
        .with_context(|| format!("fsync redacted segment {}", segment_path.display()))?;
    Ok(report)
}

/// Idempotent low-level primitive: take an open r/w file positioned
/// anywhere + a frame offset + the already-parsed header, and rewrite
/// the frame so its payload is zeros, its REDACTED flag is set, and
/// its CRC is recomputed.
///
/// Public so a future `cli/wal redact --offset N` command (manual
/// operator surgery) can call it directly. The scanner uses it
/// internally for each predicate match.
pub fn redact_frame_in_place(
    file: &mut std::fs::File,
    frame_offset: u64,
    header: &EventHeaderV2,
) -> Result<()> {
    let payload_offset =
        frame_offset + (PREAMBLE_LEN + HEADER_BODY_LEN + header.reserved_len as usize) as u64;
    let payload_len = header.payload_len as usize;
    let total_len = header.total_len as usize;

    // 1. Zero the payload.
    let zeros = vec![0u8; payload_len];
    file.seek(SeekFrom::Start(payload_offset))
        .context("seek to payload for zero-fill")?;
    file.write_all(&zeros)
        .context("write zero-fill over payload")?;

    // 2. Flip the REDACTED flag in the header. Flags live at byte 4
    // of the header body; absolute offset = frame_offset + PREAMBLE_LEN
    // + 4.
    let new_flags = (header.flags | EventFlags::REDACTED).bits();
    file.seek(SeekFrom::Start(frame_offset + PREAMBLE_LEN as u64 + 4))
        .context("seek to flags byte")?;
    file.write_all(&[new_flags])
        .context("write updated flags")?;

    // 3. Recompute CRC over the rewritten frame.
    let mut frame_buf = vec![0u8; total_len - CRC_LEN];
    file.seek(SeekFrom::Start(frame_offset))
        .context("seek to frame start for CRC recompute")?;
    file.read_exact(&mut frame_buf)
        .context("read rewritten frame for CRC")?;
    let new_crc = crc32c::crc32c(&frame_buf);
    file.seek(SeekFrom::Start(frame_offset + (total_len - CRC_LEN) as u64))
        .context("seek to CRC slot")?;
    file.write_all(&new_crc.to_le_bytes())
        .context("write new CRC")?;

    Ok(())
}

/// Predicate helper: returns true when the payload bytes contain
/// `needle` as a UTF-8 substring (case-insensitive). Matches the
/// semantics of `memory::forget::forget_by_topic` so operators get
/// "the same rows the SQLite wipe deleted" physically erased too.
pub fn payload_contains_topic(needle: &str) -> impl Fn(&[u8]) -> bool + '_ {
    let needle_lower = needle.to_ascii_lowercase();
    move |payload: &[u8]| {
        let Ok(text) = std::str::from_utf8(payload) else {
            return false;
        };
        text.to_ascii_lowercase().contains(&needle_lower)
    }
}

/// C-15 follow-up: emit a [`EVENT_TYPE_REDACTION_MARKER`] (0xF3) WAL
/// frame recording which offsets a redaction wave touched + why.
/// Future `neoth verify` reads these markers to skip the original-HMAC
/// check on the listed offsets — the HMAC mismatch is operator-
/// authorised, not adversarial.
///
/// Caller (typically `memory::forget --physical`) invokes this once
/// per touched segment after `scan_and_redact` returns, threading the
/// driving topic + source for the audit trail.
pub async fn emit_redaction_marker(
    writer: &super::writer::WalWriterHandle,
    segment_path: &std::path::Path,
    redacted_offsets: &[u64],
    bytes_redacted: u64,
    topic: &str,
    source: &str,
    now_unix: i64,
) -> anyhow::Result<u64> {
    use anyhow::Context as _;
    // Reviewer-2 P0-B fix (2026-05-20): store only the segment's
    // file_name(), not its full display() path. The verifier and the
    // writer can reach the same segment via different path forms
    // (`--wal-dir ./relative` vs absolute, symlinked dirs, OS-specific
    // separator normalisation). Comparing full paths leads to false
    // FAILs on authorised redactions that the verifier cannot recognise.
    // file_name() is stable across all those forms because the
    // filename is the identity inside a WAL directory.
    let segment_name = segment_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| segment_path.display().to_string());
    // Sign the AUTHORISATION (segment + offsets + topic + ts) with the operator's
    // ed25519 signing key. `neoth verify` only honours a redaction exemption whose
    // signature verifies against the operator's OWN public key — so a forged
    // CRC32c-only 0xF3 frame (which an attacker can write but cannot sign, the
    // key being 0600 / DPAPI-wrapped) can no longer make a tampered HMAC window
    // reclassify as PASS. Fail closed if the key can't be loaded (an
    // unauthenticatable redaction must not be emitted).
    // The signing key lives in the SAME WAL dir as the segment
    // (`<wal_dir>/signing.key`) — in production that's `~/.neoth/wal/signing.key`
    // (= the default path), and a tempdir WAL keeps its own key so the scheme is
    // self-consistent + test-isolated. `neoth verify` resolves the trust root the
    // same way (the segments' parent dir).
    let signing_key_path = segment_path
        .parent()
        .map(|p| p.join("signing.key"))
        .unwrap_or_else(crate::wal::signing::default_signing_key_path);
    let signing_key = crate::wal::signing::load_or_init_signing_key(&signing_key_path)
        .context("load operator signing key to authenticate the redaction marker")?;
    let signed_msg =
        redaction_authorisation_message(&segment_name, redacted_offsets, bytes_redacted, topic, now_unix);
    let sig = crate::wal::signing::sign_b64(&signing_key, &signed_msg);
    let signer_pubkey = crate::wal::signing::pubkey_b64(&signing_key);
    let payload = serde_json::to_vec(&serde_json::json!({
        "segment": segment_name,
        "redacted_offsets": redacted_offsets,
        "bytes_redacted": bytes_redacted,
        "topic": topic,
        "source": source,
        "ts_unix": now_unix,
        "signer_pubkey": signer_pubkey,
        "sig": sig,
    }))
    .context("serialize REDACTION_MARKER payload")?;
    let header =
        super::HeaderBuilder::new(super::events::EVENT_TYPE_REDACTION_MARKER, &payload).build();
    writer
        .append(header, payload)
        .await
        .context("append REDACTION_MARKER frame")
}

/// Canonical, deterministic bytes signed by [`emit_redaction_marker`] and
/// re-verified by `neoth verify`. A fixed `field|field|…` layout (NOT JSON, to
/// avoid any serialiser field-order dependence) over exactly the fields the
/// verifier uses to GRANT an exemption: segment name, redacted offsets, byte
/// count, topic, timestamp. Any change to those invalidates the signature.
pub(crate) fn redaction_authorisation_message(
    segment: &str,
    redacted_offsets: &[u64],
    bytes_redacted: u64,
    topic: &str,
    ts_unix: i64,
) -> Vec<u8> {
    let offsets = redacted_offsets
        .iter()
        .map(|o| o.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("redaction-marker-v1|{segment}|{offsets}|{bytes_redacted}|{topic}|{ts_unix}")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::frame::{decode_frame, encode_frame};
    use crate::wal::hlc::Hlc;
    use crate::wal::segment_header::SegmentHeader;
    use crate::wal::types::{EventId, Importance, NodeId, SessionId};

    /// Build a frame header for testing (matches the `populated_header`
    /// pattern in `wal::frame::tests` but private to this module to
    /// avoid cross-test coupling).
    fn make_header(payload_len: u32, event_id: u64) -> EventHeaderV2 {
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: 0x01,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len as usize + CRC_LEN) as u32,
            payload_len,
            generation: 1,
            event_id: EventId(event_id),
            hlc: Hlc::new(1_700_000_000_000_000_000, event_id as u32).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: 0,
            category: 0,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: 0xdeadbeef,
        }
    }

    /// Write a fresh segment file containing N frames with operator-
    /// supplied payloads. Returns the file path + the offsets where
    /// each frame lands.
    fn write_segment_with_frames(payloads: &[&[u8]]) -> (tempfile::NamedTempFile, Vec<u64>) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let mut bytes = Vec::new();
        let segment_header = SegmentHeader::new(1, 1, 0, 0, [0u8; 16]);
        bytes.extend_from_slice(&segment_header.to_le_bytes());
        let mut offsets = Vec::with_capacity(payloads.len());
        for (i, p) in payloads.iter().enumerate() {
            offsets.push(bytes.len() as u64);
            let h = make_header(p.len() as u32, (i + 1) as u64);
            let frame = encode_frame(&h, p);
            bytes.extend_from_slice(&frame);
        }
        std::fs::write(tmp.path(), &bytes).unwrap();
        (tmp, offsets)
    }

    /// Write a *live* v2 segment file: 61-byte v2 header (COMPRESSED flag set)
    /// followed by RAW frames — exactly what the writer produces before clean
    /// finalize. Returns the file path + the raw-file offsets of each frame.
    fn write_v2_live_segment_with_frames(payloads: &[&[u8]]) -> (tempfile::NamedTempFile, Vec<u64>) {
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let mut bytes = Vec::new();
        let segment_header = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        bytes.extend_from_slice(&segment_header.to_le_bytes());
        let mut offsets = Vec::with_capacity(payloads.len());
        for (i, p) in payloads.iter().enumerate() {
            offsets.push(bytes.len() as u64);
            let h = make_header(p.len() as u32, (i + 1) as u64);
            let frame = encode_frame(&h, p);
            bytes.extend_from_slice(&frame);
        }
        std::fs::write(tmp.path(), &bytes).unwrap();
        (tmp, offsets)
    }

    #[test]
    fn scan_redacts_matching_frames_in_a_v2_live_segment() {
        // GOLD-ARCH-03 regression: a live v2 segment has a 61-byte header. The
        // pre-fix hardcoded SEGMENT_HEADER_LEN (60) start offset failed the
        // MAGIC check on frame 1 and SILENTLY redacted nothing — a privacy
        // hole. With the header-length fix the matching frame is scrubbed.
        let (tmp, offsets) =
            write_v2_live_segment_with_frames(&[b"hello world", b"AcmeCorp is a secret"]);
        let report = scan_and_redact(tmp.path(), payload_contains_topic("acmecorp")).expect("redact");
        assert_eq!(report.frames_redacted_count(), 1, "v2 frame must be found");
        assert_eq!(report.frames_redacted, vec![offsets[1]]);
        assert_eq!(report.frames_skipped, 1);
    }

    #[test]
    fn scan_refuses_to_redact_a_sealed_compressed_segment() {
        // GOLD-ARCH-03: a finalised compressed segment can't be redacted by
        // in-place seek+overwrite. Refuse loudly rather than silently no-op.
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let mut raw_frames = Vec::new();
        let h = make_header(b"AcmeCorp secret".len() as u32, 1);
        raw_frames.extend_from_slice(&encode_frame(&h, b"AcmeCorp secret"));
        let blob = compress_frames(&raw_frames).expect("compress");
        let mut bytes = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&blob);
        std::fs::write(tmp.path(), &bytes).unwrap();
        let err = scan_and_redact(tmp.path(), payload_contains_topic("acme"))
            .expect_err("must refuse compressed segment");
        assert!(
            err.to_string().contains("compressed"),
            "error should name the compressed-segment refusal: {err}"
        );
    }

    #[test]
    fn scan_refuses_a_segment_with_an_unparseable_header() {
        // GR-058: a segment large enough to carry a header but whose header does
        // NOT parse is tamper-suspect — scan_and_redact must REFUSE (Err) rather
        // than guess a wrong v1 offset (60) and silently redact nothing (a
        // privacy hole, since memory::forget would then report success). FAILS
        // pre-fix (Ok, 0 frames), passes post-fix (Err).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // ≥ header length of bytes that do NOT form a valid segment header.
        std::fs::write(tmp.path(), vec![0xFFu8; SEGMENT_HEADER_LEN + 40]).unwrap();
        let err = scan_and_redact(tmp.path(), payload_contains_topic("x"))
            .expect_err("must refuse an unparseable-header segment");
        assert!(
            err.to_string().contains("header does not parse"),
            "error should name the unparseable header: {err}"
        );
    }

    #[test]
    fn scan_redacts_only_matching_frames_and_skips_others() {
        let (tmp, offsets) = write_segment_with_frames(&[
            b"hello world",
            b"AcmeCorp is a secret",
            b"another unrelated frame",
            b"more AcmeCorp data here",
        ]);
        let predicate = payload_contains_topic("acmecorp");
        let report = scan_and_redact(tmp.path(), predicate).expect("redact");
        assert_eq!(report.frames_redacted_count(), 2);
        assert_eq!(report.frames_skipped, 2);
        assert_eq!(report.already_redacted, 0);
        // Total bytes redacted = sum of the two matching payload sizes.
        assert_eq!(
            report.bytes_redacted,
            ("AcmeCorp is a secret".len() + "more AcmeCorp data here".len()) as u64
        );
        // The redacted offsets must be the 2nd + 4th frame offsets.
        assert_eq!(report.frames_redacted, vec![offsets[1], offsets[3]]);
    }

    #[test]
    fn redacted_frame_still_decodes_with_zero_payload_and_redacted_flag() {
        let (tmp, _) = write_segment_with_frames(&[b"AcmeCorp owns this row"]);
        let predicate = payload_contains_topic("acme");
        scan_and_redact(tmp.path(), predicate).expect("redact");

        // Walk the segment + decode the single frame; payload must
        // now be zeros + flag must carry REDACTED.
        let bytes = std::fs::read(tmp.path()).unwrap();
        let frame_slice = &bytes[SEGMENT_HEADER_LEN..];
        let decoded = decode_frame(frame_slice).expect("decode redacted frame");
        assert!(decoded.header.flags.contains(EventFlags::REDACTED));
        assert!(
            decoded.payload.iter().all(|b| *b == 0),
            "payload must be all zeros, got: {:?}",
            decoded.payload
        );
        // Original event_id + payload_hash preserved as chain-of-
        // evidence anchors.
        assert_eq!(decoded.header.event_id.0, 1);
        assert_eq!(decoded.header.payload_hash, 0xdeadbeef);
    }

    #[test]
    fn redaction_is_idempotent_already_redacted_frames_are_skipped() {
        let (tmp, _) = write_segment_with_frames(&[b"AcmeCorp row"]);
        let pred = payload_contains_topic("acme");
        let first = scan_and_redact(tmp.path(), pred).unwrap();
        assert_eq!(first.frames_redacted_count(), 1);
        // Second pass: the same predicate would match again on a
        // fresh frame, but the REDACTED flag now blocks the scan
        // from touching it twice.
        let pred2 = payload_contains_topic("acme");
        let second = scan_and_redact(tmp.path(), pred2).unwrap();
        assert_eq!(second.frames_redacted_count(), 0);
        assert_eq!(second.already_redacted, 1);
    }

    #[test]
    fn scan_returns_empty_report_on_segment_with_no_matches() {
        let (tmp, _) = write_segment_with_frames(&[b"alpha", b"beta", b"gamma"]);
        let pred = payload_contains_topic("nothing-matches-this");
        let report = scan_and_redact(tmp.path(), pred).unwrap();
        assert_eq!(report.frames_redacted_count(), 0);
        assert_eq!(report.frames_skipped, 3);
        assert_eq!(report.bytes_redacted, 0);
    }

    #[test]
    fn scan_handles_segment_with_only_header_no_frames() {
        // A freshly-rotated segment that holds only its 60-byte
        // segment header must yield an empty report, not panic.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let h = SegmentHeader::new(1, 1, 0, 0, [0u8; 16]);
        std::fs::write(tmp.path(), h.to_le_bytes()).unwrap();
        let pred = payload_contains_topic("anything");
        let report = scan_and_redact(tmp.path(), pred).unwrap();
        assert_eq!(report.frames_redacted_count(), 0);
        assert_eq!(report.frames_skipped, 0);
    }

    #[test]
    fn payload_contains_topic_is_case_insensitive() {
        let pred = payload_contains_topic("ACME");
        assert!(pred(b"contains acme inside"));
        assert!(pred(b"ACME at start"));
        assert!(pred(b"Acme in mixed case"));
        assert!(!pred(b"no match here"));
    }

    #[test]
    fn payload_contains_topic_returns_false_for_non_utf8() {
        // Frames carrying binary payloads (audio, images) MUST NOT
        // match a text-topic predicate even if they accidentally
        // contain the topic bytes — the predicate scopes to text-only
        // matches so binary frames stay intact.
        let pred = payload_contains_topic("acme");
        // Invalid UTF-8 sequence.
        assert!(!pred(&[0xff, 0xfe, 0xfd, b'a', b'c', b'm', b'e']));
    }

    #[test]
    fn redact_preserves_frame_offset_layout() {
        // The scanner must NOT shift subsequent frame offsets; this
        // is the load-bearing invariant for indexer + recall reading
        // the rotated segment correctly after redaction.
        let (tmp, offsets) = write_segment_with_frames(&[
            b"frame-A keep",
            b"frame-B AcmeCorp redact me",
            b"frame-C keep",
        ]);
        let pred = payload_contains_topic("acme");
        scan_and_redact(tmp.path(), pred).unwrap();

        let bytes = std::fs::read(tmp.path()).unwrap();
        // Walk all three frames + assert each starts at its original
        // offset. If redaction shifted the layout, decode_frame on
        // offset[2] would either fail or read garbage.
        for (i, off) in offsets.iter().enumerate() {
            let frame = decode_frame(&bytes[*off as usize..]).expect("decode at offset");
            // The original event_id was (i+1) per make_header.
            assert_eq!(frame.header.event_id.0, (i + 1) as u64);
        }
    }

    #[tokio::test]
    async fn emit_redaction_marker_writes_authoritative_audit_frame() {
        use crate::wal::events::EVENT_TYPE_REDACTION_MARKER;
        use crate::wal::frame::decode_frame;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        use tokio::fs::read;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("marker-audit.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        // Real path in the tempdir so the operator signing key can be created
        // alongside it (mirrors production: segment + marker + key share a dir).
        let target_segment = dir.path().join("000001.wal");
        let offsets = vec![100u64, 250u64, 410u64];
        let _ = emit_redaction_marker(
            &writer,
            &target_segment,
            &offsets,
            42,
            "AcmeCorp",
            "cli",
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;

        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode");
            if frame.header.event_type == EVENT_TYPE_REDACTION_MARKER {
                let p: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let payload = found.expect("REDACTION_MARKER must be present");
        assert!(payload["segment"].as_str().unwrap().ends_with("000001.wal"));
        let recorded_offsets: Vec<u64> = payload["redacted_offsets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(recorded_offsets, offsets);
        assert_eq!(payload["bytes_redacted"], 42);
        assert_eq!(payload["topic"], "AcmeCorp");
        assert_eq!(payload["source"], "cli");
        assert_eq!(payload["ts_unix"], 1_700_000_000_i64);
        // The marker is now operator-SIGNED — verify only honours authenticated
        // exemptions, so the signature + pubkey must be present.
        assert!(payload["signer_pubkey"].as_str().is_some(), "marker carries operator pubkey");
        assert!(payload["sig"].as_str().is_some(), "marker is signed");
    }
}
