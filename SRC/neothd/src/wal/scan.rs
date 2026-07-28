//! GOLD-ARCH-03 — the single v2-transparent WAL frame iterator.
//!
//! Every caller that scans a sealed segment's frames should go through
//! [`for_each_frame`] (or [`super::compaction::logical_segment_bytes`] directly
//! when it also needs the reconstructed byte slice for windowing, e.g. HMAC
//! marker verification). The hazard this closes: a finalized COMPRESSED (v2)
//! segment stores its frames as one zstd blob after a 61-byte header. Callers
//! that skipped a hard-coded `SEGMENT_HEADER_LEN` (60) and ran `decode_frame`
//! over the RAW file bytes therefore (a) misaligned by 1 byte even on an
//! uncompressed v2 segment, and (b) silently saw ZERO frames on every
//! compressed segment — the indexer dropped events, rollback/undo lost
//! snapshots, audits read nothing. `for_each_frame` reconstructs the logical
//! (decompressed) bytes once via `logical_segment_bytes`, then walks frames
//! from the correct header offset.

use std::ffi::OsString;
use std::path::Path;

use anyhow::{Context, Result};

use super::compaction::{logical_segment_bytes, logical_segment_bytes_with_key_capped};
use super::frame::{DecodedFrame, decode_frame};
use super::segment_header::{ParsedSegmentHeader, SEGMENT_HEADER_LEN, parse_segment_header};

pub(crate) const MAX_HOME_KEY_BYTES: usize = 16 * 1024;
const MAX_HOME_HMAC_ARCHIVES: usize = 64;
// Key discovery walks the same `<home>/wal` namespace as the segment scan.
// Its all-entry ceiling must therefore admit every directory the WAL scanner
// itself considers valid; otherwise an old/high-volume home can write WAL
// successfully but can no longer authenticate a pending Skill mutation.
pub(crate) const MAX_HOME_KEY_DIRECTORY_ENTRIES: usize = 8192;

/// Bounded work contract for security-sensitive instance-home scans.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HomeWalScanLimits {
    pub max_directory_entries: usize,
    pub max_segments: usize,
    pub max_segment_physical_bytes: usize,
    pub max_total_physical_bytes: u64,
    pub max_segment_logical_bytes: u64,
    pub max_total_logical_bytes: u64,
}

impl Default for HomeWalScanLimits {
    fn default() -> Self {
        Self {
            max_directory_entries: 8192,
            max_segments: 4096,
            max_segment_physical_bytes: 32 * 1024 * 1024,
            max_total_physical_bytes: 1024 * 1024 * 1024,
            max_segment_logical_bytes: 64 * 1024 * 1024,
            max_total_logical_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Immutable physical identity/order metadata for one decoded home-WAL frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HomeWalFrameLocation {
    pub segment_name: OsString,
    pub segment_generation: u32,
    pub segment_seq: u64,
    pub segment_start_ts_ns: u64,
    pub segment_node_id: [u8; 16],
    pub logical_offset: u64,
}

/// Load the active HMAC key plus bounded, capability-read rotation archives.
/// A crash-recovered Skill operation may legitimately span an operator key
/// rotation while the daemon is stopped; its already-durable intent remains
/// authority only if the exact archived predecessor verifies it.
pub(crate) fn load_home_hmac_keys(home: &Path) -> Result<Vec<Vec<u8>>> {
    load_home_hmac_keys_with_limits(home, MAX_HOME_HMAC_ARCHIVES, MAX_HOME_KEY_DIRECTORY_ENTRIES)
}

fn load_home_hmac_keys_with_limits(
    home: &Path,
    max_archives: usize,
    max_directory_entries: usize,
) -> Result<Vec<Vec<u8>>> {
    let wal_path = home.join("wal");
    let Some(root) =
        crate::skills::store::open_bound_directory(&wal_path, false, "WAL key archive root")?
    else {
        return Ok(Vec::new());
    };
    let active_name = std::ffi::OsStr::new("hmac.key");
    let active_display = root.display_path.join(active_name);
    let active = crate::skills::store::read_regular_file_bounded(
        &root.dir,
        active_name,
        &active_display,
        MAX_HOME_KEY_BYTES,
    )
    .with_context(|| {
        format!(
            "read capability-bound active WAL HMAC key {}",
            active_display.display()
        )
    })?;
    let mut names = Vec::<OsString>::new();
    let mut examined_entries = 0usize;
    for entry in root
        .dir
        .entries()
        .with_context(|| format!("enumerate WAL key archives {}", wal_path.display()))?
    {
        examined_entries = examined_entries
            .checked_add(1)
            .context("WAL key directory-entry counter overflow")?;
        if examined_entries > max_directory_entries {
            anyhow::bail!(
                "WAL key scan exceeds the {}-entry directory limit under {}",
                max_directory_entries,
                wal_path.display()
            );
        }
        let name = entry
            .with_context(|| format!("read WAL key archive under {}", wal_path.display()))?
            .file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        if text.starts_with("hmac.key.") && text.ends_with(".archive") {
            let timestamp = &text["hmac.key.".len()..text.len() - ".archive".len()];
            if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
                anyhow::bail!(
                    "WAL scan refuses malformed HMAC key archive name under {}",
                    wal_path.display()
                );
            }
            if names.len() >= max_archives {
                anyhow::bail!(
                    "WAL scan exceeds the {}-archive HMAC key limit",
                    max_archives
                );
            }
            names.push(name);
        }
    }
    names.sort();
    let mut keys = Vec::with_capacity(names.len() + 1);
    keys.push(crate::wal::compaction::decode_existing_key(
        &active,
        &active_display,
    )?);
    for name in names {
        let display = root.display_path.join(&name);
        let body = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            &name,
            &display,
            MAX_HOME_KEY_BYTES,
        )
        .with_context(|| {
            format!(
                "read capability-bound WAL HMAC key archive {}",
                display.display()
            )
        })?;
        keys.push(crate::wal::compaction::decode_existing_key(
            &body, &display,
        )?);
    }
    Ok(keys)
}

fn load_home_segment_key(
    root: &crate::skills::store::BoundDirectory,
) -> Result<Option<crate::wal::crypto::WalSegmentKey>> {
    let name = std::ffi::OsStr::new("master.key");
    match root.dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect capability-bound WAL master key {}",
                    root.display_path.join(name).display()
                )
            });
        }
        Ok(_) => {}
    }
    let display = root.display_path.join(name);
    let body = crate::skills::store::read_regular_file_bounded(
        &root.dir,
        name,
        &display,
        MAX_HOME_KEY_BYTES,
    )
    .with_context(|| format!("read capability-bound WAL master key {}", display.display()))?;
    let raw = crate::wal::compaction::decode_existing_key(&body, &display)?;
    let master = crate::wal::crypto::WalMasterKey::from_bytes(&raw)
        .with_context(|| format!("decode WAL master key {}", display.display()))?;
    crate::wal::crypto::derive_subkey(&master, crate::wal::crypto::INFO_WAL_SEGMENT).map(Some)
}

pub(crate) fn canonical_segment_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".wal") else {
        return false;
    };
    let (namespace, sequence) = match stem.rsplit_once('-') {
        Some((namespace, sequence)) => (Some(namespace), sequence),
        None => (None, stem),
    };
    if sequence.len() != 6 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    namespace.is_none_or(|namespace| {
        !namespace.is_empty()
            && namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

/// Iterate every frame in a WAL segment, transparently handling v1 (plain) and
/// v2 (zstd-compressed) segments. `cb` receives `(cursor, &frame)` where
/// `cursor` is the frame's byte offset inside the LOGICAL (decompressed)
/// segment — identical to the offset v1 callers already tracked, and the value
/// the `wal_cursor` table + rollback `absolute_offset` are measured in.
///
/// Stops cleanly at a SHORT trailing frame (a crashed writer may leave the last
/// frame incomplete → `decode_frame` returns `BufferTooShort`), guards against a
/// `total_len == 0` infinite loop, and treats a segment shorter than a header as
/// empty (not an error). GR-059 — a NON-short decode failure mid-segment
/// (`CrcMismatch`, `InvalidMagic`, `InconsistentTotalLen`, bad version/flags, …)
/// means a fully-present frame failed to validate, i.e. corruption or tampering;
/// it is returned as an error (fail loud) rather than read as a clean
/// end-of-data. Also returns the first error from `cb` (a caller may `bail!` to
/// abort the walk early) or from an unreconstructable compressed blob.
pub(crate) fn for_each_frame<F>(seg_bytes: &[u8], mut cb: F) -> Result<()>
where
    F: FnMut(usize, &DecodedFrame<'_>) -> Result<()>,
{
    if seg_bytes.len() < SEGMENT_HEADER_LEN {
        return Ok(());
    }
    let (header_len, logical) = logical_segment_bytes(seg_bytes)?;
    for_each_logical_frame(&logical, header_len, &mut cb)
}

fn for_each_logical_frame<F>(logical: &[u8], header_len: usize, cb: &mut F) -> Result<()>
where
    F: FnMut(usize, &DecodedFrame<'_>) -> Result<()>,
{
    let mut cursor = header_len;
    while cursor < logical.len() {
        let dec = match decode_frame(&logical[cursor..]) {
            Ok(d) => d,
            // GR-059 — a benign torn/short trailing frame (crashed writer) shows
            // up ONLY as `BufferTooShort` (decode_frame maps an incomplete header
            // OR body to it). Stop walking cleanly for that. Every OTHER
            // HeaderParseError means a fully-present frame failed to validate —
            // corruption or tampering — which must fail loud, not be read as a
            // clean end-of-data (the old `Err(_) => break` silently truncated the
            // scan on a CRC mismatch / bad magic mid-segment).
            Err(super::error::HeaderParseError::BufferTooShort { .. }) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "wal::scan: tamper-suspect frame at logical offset {cursor}: {e} \
                     (a fully-present frame failed to validate mid-segment — corruption \
                     or tampering, not a torn tail)"
                ));
            }
        };
        let total = dec.header.total_len as usize;
        if total == 0 {
            // Defensive: a zero-length frame would loop forever.
            break;
        }
        cb(cursor, &dec)?;
        cursor += total;
    }
    Ok(())
}

/// Enumerate every real regular `.wal` child of `<home>/wal` through the
/// capability-bound store, reconstruct it with the explicit instance-home key,
/// and walk frames under per-segment and aggregate physical/logical caps.
///
/// A `.wal` symlink, reparse point, FIFO/device or directory is an integrity
/// error. It is never skipped and never followed.
pub(crate) fn for_each_frame_at_home<F>(
    home: &Path,
    limits: HomeWalScanLimits,
    mut cb: F,
) -> Result<()>
where
    F: FnMut(&HomeWalFrameLocation, &DecodedFrame<'_>) -> Result<()>,
{
    let wal_path = home.join("wal");
    let Some(root) = crate::skills::store::open_bound_directory(&wal_path, false, "WAL scan root")?
    else {
        return Ok(());
    };
    let segment_key = load_home_segment_key(&root)?;
    let mut names = Vec::<OsString>::new();
    let mut examined_entries = 0usize;
    for entry in root
        .dir
        .entries()
        .with_context(|| format!("enumerate WAL scan root {}", wal_path.display()))?
    {
        examined_entries = examined_entries
            .checked_add(1)
            .context("WAL directory-entry counter overflow")?;
        if examined_entries > limits.max_directory_entries {
            anyhow::bail!(
                "WAL scan exceeds the {}-entry directory limit under {}",
                limits.max_directory_entries,
                wal_path.display()
            );
        }
        let entry =
            entry.with_context(|| format!("read WAL entry under {}", wal_path.display()))?;
        let name = entry.file_name();
        if Path::new(&name)
            .extension()
            .and_then(|value| value.to_str())
            == Some("wal")
        {
            if !canonical_segment_name(&name) {
                anyhow::bail!(
                    "WAL scan refuses non-canonical segment name under {}",
                    wal_path.display()
                );
            }
            if names.len() >= limits.max_segments {
                anyhow::bail!("WAL scan exceeds the {}-segment limit", limits.max_segments);
            }
            names.push(name);
        }
    }
    names.sort();

    let mut total_physical = 0u64;
    let mut total_logical = 0u64;
    for name in names {
        let display = root.display_path.join(&name);
        let raw = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            &name,
            &display,
            limits.max_segment_physical_bytes,
        )
        .with_context(|| {
            format!(
                "read capability-bound regular WAL segment {}",
                display.display()
            )
        })?;
        total_physical = total_physical
            .checked_add(raw.len() as u64)
            .context("aggregate WAL physical-byte counter overflow")?;
        if total_physical > limits.max_total_physical_bytes {
            anyhow::bail!(
                "WAL scan exceeds the {}-byte aggregate physical limit",
                limits.max_total_physical_bytes
            );
        }

        let parsed = parse_segment_header(&raw)
            .with_context(|| format!("parse WAL segment header {}", display.display()))?;
        let (header_len, logical) = logical_segment_bytes_with_key_capped(
            &raw,
            segment_key.as_ref(),
            limits.max_segment_logical_bytes,
        )
        .with_context(|| format!("reconstruct home-bound WAL segment {}", display.display()))?;
        total_logical = total_logical
            .checked_add(logical.len() as u64)
            .context("aggregate WAL logical-byte counter overflow")?;
        if total_logical > limits.max_total_logical_bytes {
            anyhow::bail!(
                "WAL scan exceeds the {}-byte aggregate logical limit",
                limits.max_total_logical_bytes
            );
        }
        scan_one_home_segment(&name, parsed, &logical, header_len, &mut cb)?;
    }
    Ok(())
}

fn scan_one_home_segment<F>(
    name: &OsString,
    parsed: ParsedSegmentHeader,
    logical: &[u8],
    header_len: usize,
    cb: &mut F,
) -> Result<()>
where
    F: FnMut(&HomeWalFrameLocation, &DecodedFrame<'_>) -> Result<()>,
{
    for_each_logical_frame(logical, header_len, &mut |cursor, frame| {
        let location = HomeWalFrameLocation {
            segment_name: name.clone(),
            segment_generation: parsed.generation(),
            segment_seq: parsed.segment_seq(),
            segment_start_ts_ns: parsed.segment_start_ts_ns(),
            segment_node_id: parsed.node_id(),
            logical_offset: u64::try_from(cursor).context("WAL frame offset exceeds u64")?,
        };
        cb(&location, frame)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::compress::compress_frames;
    use crate::wal::crypto::{encrypt_blob, frame_encrypted};
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::{
        SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
    };
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn key_discovery_accepts_every_directory_the_wal_scan_accepts() {
        assert_eq!(
            MAX_HOME_KEY_DIRECTORY_ENTRIES,
            HomeWalScanLimits::default().max_directory_entries
        );
    }

    fn frame_bytes(event_type: u8, payload: &[u8]) -> Vec<u8> {
        let h = HeaderBuilder::new(event_type, payload).build();
        encode_frame(&h, payload)
    }

    /// Three distinct frames concatenated, plus each frame's length.
    fn three_frames() -> (Vec<u8>, Vec<usize>) {
        let f1 = frame_bytes(0x01, b"one");
        let f2 = frame_bytes(0x02, b"two-two");
        let f3 = frame_bytes(0x03, b"three-three-three");
        let lens = vec![f1.len(), f2.len(), f3.len()];
        let mut all = Vec::new();
        all.extend_from_slice(&f1);
        all.extend_from_slice(&f2);
        all.extend_from_slice(&f3);
        (all, lens)
    }

    fn uncompressed_segment(frames: &[u8]) -> Vec<u8> {
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], 0);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(frames);
        seg
    }

    fn compressed_segment(frames: &[u8]) -> Vec<u8> {
        let blob = compress_frames(frames).unwrap();
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(&blob);
        seg
    }

    fn write_home_segment(home: &Path, name: &str, bytes: &[u8]) {
        let wal = home.join("wal");
        fs::create_dir_all(&wal).unwrap();
        fs::write(wal.join(name), bytes).unwrap();
    }

    fn write_home_hmac_key(home: &Path) {
        let wal = home.join("wal");
        fs::create_dir_all(&wal).unwrap();
        fs::write(wal.join("hmac.key"), [7u8; 32]).unwrap();
    }

    #[test]
    fn empty_or_short_segment_yields_no_frames() {
        let mut called = 0;
        for_each_frame(&[0u8; 10], |_, _| {
            called += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(called, 0);
    }

    #[test]
    fn uncompressed_segment_yields_all_frames_with_logical_cursors() {
        let (frames, lens) = three_frames();
        let seg = uncompressed_segment(&frames);
        let mut seen: Vec<(usize, u8, Vec<u8>)> = Vec::new();
        for_each_frame(&seg, |cursor, dec| {
            seen.push((cursor, dec.header.event_type, dec.payload.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 3);
        // Cursors are measured inside the logical slice (header_len = 61 here).
        assert_eq!(seen[0].0, SEGMENT_HEADER_V2_LEN);
        assert_eq!(seen[1].0, SEGMENT_HEADER_V2_LEN + lens[0]);
        assert_eq!(seen[2].0, SEGMENT_HEADER_V2_LEN + lens[0] + lens[1]);
        assert_eq!(seen[0].1, 0x01);
        assert_eq!(seen[2].2, b"three-three-three");
    }

    #[test]
    fn compressed_v2_segment_yields_all_frames() {
        // THE BUG FIX: a raw-byte scanner (skip 60 + decode_frame on the file
        // bytes) sees ZERO frames here because the body is a zstd blob.
        let (frames, _) = three_frames();
        let seg = compressed_segment(&frames);
        let mut seen: Vec<u8> = Vec::new();
        for_each_frame(&seg, |_, dec| {
            seen.push(dec.header.event_type);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![0x01, 0x02, 0x03],
            "every frame inside the zstd blob must be iterated, not skipped"
        );
    }

    #[test]
    fn torn_tail_after_good_frames_is_silently_skipped() {
        let (frames, _) = three_frames();
        let mut seg = uncompressed_segment(&frames);
        // A REALISTIC torn tail: the writer crashed mid-frame, leaving a valid
        // magic + a truncated remainder → `BufferTooShort`. (GR-059: this is the
        // ONLY benign decode failure; see the tamper test below.)
        let partial = frame_bytes(0x01, b"payload-that-was-being-written");
        seg.extend_from_slice(&partial[..partial.len().min(12)]);
        let mut called = 0;
        for_each_frame(&seg, |_, _| {
            called += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            called, 3,
            "the short torn tail after the 3 good frames is dropped"
        );
    }

    #[test]
    fn corrupt_frame_mid_segment_fails_loud_gr059() {
        // GR-059 — a fully-present frame region that fails to validate (here a
        // bad magic over a header-length block, the InvalidMagic case) is NOT a
        // torn tail; it must fail loud, not silently truncate the scan as the
        // old `Err(_) => break` did.
        let (frames, _) = three_frames();
        let mut seg = uncompressed_segment(&frames);
        seg.extend_from_slice(&[0xAB; 200]); // long enough to clear the header → InvalidMagic
        let r = for_each_frame(&seg, |_, _| Ok(()));
        assert!(
            r.is_err(),
            "a non-BufferTooShort decode error must fail loud"
        );
        assert!(
            format!("{:?}", r.unwrap_err()).contains("tamper-suspect"),
            "the error must name the tamper-suspect cause"
        );
    }

    #[test]
    fn cb_error_aborts_the_walk_early() {
        let (frames, _) = three_frames();
        let seg = uncompressed_segment(&frames);
        let mut called = 0;
        let r = for_each_frame(&seg, |_, _| {
            called += 1;
            if called == 2 {
                anyhow::bail!("caller stop");
            }
            Ok(())
        });
        assert!(r.is_err(), "a cb error propagates out of the walk");
        assert_eq!(called, 2, "the walk stops at the failing frame");
    }

    #[test]
    fn home_scan_requires_a_canonical_segment_name_and_real_header() {
        let dir = tempdir().unwrap();
        let frame = frame_bytes(0x01, b"payload");
        write_home_segment(dir.path(), "1.wal", &uncompressed_segment(&frame));
        let error = for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
            .unwrap_err();
        assert!(format!("{error:#}").contains("non-canonical"));

        fs::remove_file(dir.path().join("wal/1.wal")).unwrap();
        write_home_segment(dir.path(), "000001.wal", &frame);
        let error = for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
            .unwrap_err();
        assert!(format!("{error:#}").contains("segment header"));
    }

    #[test]
    fn home_scan_enforces_segment_and_aggregate_byte_caps() {
        let dir = tempdir().unwrap();
        let segment = uncompressed_segment(&frame_bytes(0x01, b"bounded"));
        write_home_segment(dir.path(), "000001.wal", &segment);

        let mut limits = HomeWalScanLimits::default();
        limits.max_segment_physical_bytes = segment.len() - 1;
        let error = for_each_frame_at_home(dir.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));

        let mut limits = HomeWalScanLimits::default();
        limits.max_total_physical_bytes = (segment.len() - 1) as u64;
        let error = for_each_frame_at_home(dir.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("aggregate physical"));

        let mut limits = HomeWalScanLimits::default();
        limits.max_segment_logical_bytes = 1;
        let error = for_each_frame_at_home(dir.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("scanner cap"));

        let mut limits = HomeWalScanLimits::default();
        limits.max_total_logical_bytes = (segment.len() - 1) as u64;
        let error = for_each_frame_at_home(dir.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("aggregate logical"));
    }

    #[test]
    fn home_scan_bounds_matching_segments_and_all_directory_entries() {
        let segments = tempdir().unwrap();
        let segment = uncompressed_segment(&frame_bytes(0x01, b"bounded"));
        write_home_segment(segments.path(), "000001.wal", &segment);
        write_home_segment(segments.path(), "000002.wal", &segment);

        let mut limits = HomeWalScanLimits::default();
        limits.max_segments = 1;
        let error = for_each_frame_at_home(segments.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("1-segment limit"));

        let unrelated = tempdir().unwrap();
        let wal = unrelated.path().join("wal");
        fs::create_dir_all(&wal).unwrap();
        fs::write(wal.join("junk-one"), b"").unwrap();
        fs::write(wal.join("junk-two"), b"").unwrap();

        let mut limits = HomeWalScanLimits::default();
        limits.max_directory_entries = 1;
        let error = for_each_frame_at_home(unrelated.path(), limits, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("1-entry directory limit"));
    }

    #[test]
    fn home_hmac_key_scan_bounds_archives_and_all_directory_entries() {
        let archives = tempdir().unwrap();
        write_home_hmac_key(archives.path());
        let wal = archives.path().join("wal");
        fs::write(wal.join("hmac.key.1.archive"), [1u8; 32]).unwrap();
        fs::write(wal.join("hmac.key.2.archive"), [2u8; 32]).unwrap();
        let error = load_home_hmac_keys_with_limits(archives.path(), 1, 8).unwrap_err();
        assert!(format!("{error:#}").contains("1-archive HMAC key limit"));

        let unrelated = tempdir().unwrap();
        write_home_hmac_key(unrelated.path());
        let wal = unrelated.path().join("wal");
        fs::write(wal.join("junk-one"), b"").unwrap();
        fs::write(wal.join("junk-two"), b"").unwrap();
        let error = load_home_hmac_keys_with_limits(unrelated.path(), 64, 2).unwrap_err();
        assert!(format!("{error:#}").contains("2-entry directory limit"));
    }

    #[test]
    fn encrypted_segment_is_bound_to_its_explicit_instance_home_key() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let frames = frame_bytes(0x01, b"custom-home");
        let header = SegmentHeaderV2::new(7, 1, 0, 42, [3u8; 16], 0)
            .to_le_bytes()
            .to_vec();
        let key = crate::wal::master_key::writer_segment_key_at(first.path()).unwrap();
        let nonce = [7u8; 12];
        let ciphertext = encrypt_blob(&key, &nonce, &header, &frames).unwrap();
        let mut segment = header;
        segment.extend_from_slice(&frame_encrypted(&nonce, &ciphertext));
        write_home_segment(first.path(), "000001.wal", &segment);

        let mut seen = 0;
        for_each_frame_at_home(
            first.path(),
            HomeWalScanLimits::default(),
            |location, frame| {
                seen += 1;
                assert_eq!(location.segment_generation, 7);
                assert_eq!(frame.payload, b"custom-home");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, 1);

        crate::wal::master_key::writer_segment_key_at(second.path()).unwrap();
        write_home_segment(second.path(), "000001.wal", &segment);
        let error =
            for_each_frame_at_home(second.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .unwrap_err();
        assert!(format!("{error:#}").contains("decrypt"));
    }

    #[cfg(unix)]
    #[test]
    fn home_scan_rejects_symlink_and_fifo_segment_children() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(
            &outside,
            uncompressed_segment(&frame_bytes(0x01, b"outside")),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("wal")).unwrap();
        symlink(&outside, dir.path().join("wal/000001.wal")).unwrap();
        assert!(
            for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .is_err()
        );

        fs::remove_file(dir.path().join("wal/000001.wal")).unwrap();
        let fifo = std::ffi::CString::new(
            dir.path()
                .join("wal/000001.wal")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(
            for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .is_err()
        );

        let key_dir = tempdir().unwrap();
        fs::create_dir_all(key_dir.path().join("wal")).unwrap();
        fs::write(key_dir.path().join("outside-master.key"), [7u8; 32]).unwrap();
        symlink(
            key_dir.path().join("outside-master.key"),
            key_dir.path().join("wal/master.key"),
        )
        .unwrap();
        write_home_segment(
            key_dir.path(),
            "000001.wal",
            &uncompressed_segment(&frame_bytes(0x01, b"plain")),
        );
        assert!(
            for_each_frame_at_home(key_dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .is_err(),
            "a linked key child is an integrity error even when the current segment is plaintext"
        );
    }
}
