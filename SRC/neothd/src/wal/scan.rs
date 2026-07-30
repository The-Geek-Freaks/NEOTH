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
use sha2::{Digest as _, Sha256};

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
// Older writers rotated only after the current offset crossed 16 MiB, so one
// additional maximum frame (16 MiB payload + 104-byte envelope) could land in
// that segment. A sealed zstd/encryption representation may add bounded codec
// framing; reserve 1 MiB so valid pre-projected-rotation segments remain
// reopenable without turning recovery reads into an unbounded allocation.
const LEGACY_ROTATION_TARGET_BYTES: usize = 16 * 1024 * 1024;
const LEGACY_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024 + 104;
const LEGACY_SEAL_ENVELOPE_BYTES: usize = 1024 * 1024;
pub(crate) const LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES: usize =
    LEGACY_ROTATION_TARGET_BYTES + LEGACY_MAX_FRAME_BYTES + LEGACY_SEAL_ENVELOPE_BYTES;

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
            max_segment_physical_bytes: LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES,
            max_total_physical_bytes: 1024 * 1024 * 1024,
            max_segment_logical_bytes: 64 * 1024 * 1024,
            max_total_logical_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Limits aligned with the largest WAL home the production quota guard admits.
///
/// Security-sensitive full-home consumers must not use the smaller diagnostic
/// default or a healthy daemon can write a valid home that those consumers can
/// never read again.
pub(crate) fn supported_home_scan_limits() -> HomeWalScanLimits {
    home_scan_limits_for_quota(crate::daemon::quota::DEFAULT_CEILING_BYTES)
}

pub(crate) fn home_scan_limits_for_quota(quota_bytes: u64) -> HomeWalScanLimits {
    HomeWalScanLimits {
        max_total_physical_bytes: quota_bytes,
        max_total_logical_bytes: quota_bytes.saturating_mul(2),
        ..HomeWalScanLimits::default()
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

/// Authenticated recovery cursor for one exact rotating WAL namespace.
///
/// The cursor intentionally binds the immutable segment-header identity as well
/// as the next logical frame offset. A caller may resume only when the same
/// direct-child segment still has the same header identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HomeWalFrontier {
    pub segment_name: String,
    pub segment_generation: u32,
    pub segment_seq: u64,
    pub segment_start_ts_ns: u64,
    pub segment_node_id: [u8; 16],
    pub next_logical_offset: u64,
}

struct AuthenticatedHomeSegment {
    namespace: Option<String>,
    sequence: u64,
    name: OsString,
    parsed: ParsedSegmentHeader,
    physical_len: u64,
    physical_sha256_hex: String,
    logical: Vec<u8>,
    header_len: usize,
    allow_torn_tail: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentRolloverLink {
    link_domain: String,
    link_version: u8,
    closed_segment_name: String,
    closed_generation: u32,
    closed_seq: u64,
    closed_bytes: u64,
    closed_start_ts_ns: u64,
    closed_node_id: [u8; 16],
    closed_physical_bytes: u64,
    closed_sha256_hex: String,
    opened_segment_name: String,
    opened_generation: u32,
    opened_seq: u64,
    opened_start_ts_ns: u64,
    opened_node_id: [u8; 16],
    reason: String,
    ts_ns: u64,
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
            names.push(name);
        }
    }
    names.sort();
    // Never silently discard an archived verifier key. Until segment
    // retention is durably coupled to key-archive retention, an older WAL
    // segment may still require any one of these keys. Truncating the list
    // would turn an otherwise valid authenticated history into an incomplete
    // scan, so crossing the explicit bound fails closed.
    if names.len() > max_archives {
        anyhow::bail!(
            "WAL key scan exceeds the {}-archive HMAC key limit under {}",
            max_archives,
            wal_path.display()
        );
    }
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
    canonical_segment_parts(name).is_some()
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
    for_each_logical_frame(&logical, header_len, true, &mut cb)
}

fn for_each_logical_frame<F>(
    logical: &[u8],
    header_len: usize,
    allow_torn_tail: bool,
    cb: &mut F,
) -> Result<()>
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
            Err(super::error::HeaderParseError::BufferTooShort { .. }) if allow_torn_tail => break,
            Err(super::error::HeaderParseError::BufferTooShort { .. }) => {
                anyhow::bail!(
                    "wal::scan: truncated frame at logical offset {cursor} in a sealed \
                     predecessor segment"
                )
            }
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
    let mut segments = Vec::<(Option<String>, u64, OsString)>::new();
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
            if segments.len() >= limits.max_segments {
                anyhow::bail!("WAL scan exceeds the {}-segment limit", limits.max_segments);
            }
            let (namespace, sequence) = canonical_segment_parts(&name)
                .context("validated WAL segment name did not expose canonical parts")?;
            segments.push((namespace.map(str::to_owned), sequence, name));
        }
    }
    segments.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for index in 0..segments.len() {
        let (namespace, sequence, _) = &segments[index];
        let starts_namespace =
            index == 0 || segments[index - 1].0.as_deref() != namespace.as_deref();
        if starts_namespace {
            anyhow::ensure!(
                *sequence == 1,
                "WAL namespace {:?} begins at sequence {sequence} instead of 1",
                namespace.as_deref().unwrap_or("<daemon>")
            );
        } else {
            let previous = segments[index - 1].1;
            anyhow::ensure!(
                *sequence == previous.saturating_add(1),
                "WAL namespace {:?} is non-contiguous between sequences {previous} and {sequence}",
                namespace.as_deref().unwrap_or("<daemon>")
            );
        }
    }
    if segments.is_empty() {
        return Ok(());
    }
    let verification_keys =
        load_home_hmac_keys(home).context("load HMAC keys for authenticated full WAL scan")?;

    let mut total_physical = 0u64;
    let mut total_logical = 0u64;
    let mut authenticated_segments = Vec::with_capacity(segments.len());
    for index in 0..segments.len() {
        let (namespace, sequence, name) = &segments[index];
        let ends_namespace =
            index + 1 == segments.len() || segments[index + 1].0.as_deref() != namespace.as_deref();
        let display = root.display_path.join(name);
        let raw = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            name,
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
        anyhow::ensure!(
            parsed.segment_seq() == *sequence,
            "WAL segment {} header sequence {} differs from file sequence {sequence}",
            display.display(),
            parsed.segment_seq()
        );
        let (header_len, logical) = logical_segment_bytes_with_key_capped(
            &raw,
            segment_key.as_ref(),
            limits.max_segment_logical_bytes,
        )
        .with_context(|| format!("reconstruct home-bound WAL segment {}", display.display()))?;
        let logical = logical.into_owned();
        let physical_len =
            u64::try_from(raw.len()).context("WAL segment physical length exceeds u64")?;
        let physical_sha256_hex = hex::encode(Sha256::digest(&raw));
        total_logical = total_logical
            .checked_add(logical.len() as u64)
            .context("aggregate WAL logical-byte counter overflow")?;
        if total_logical > limits.max_total_logical_bytes {
            anyhow::bail!(
                "WAL scan exceeds the {}-byte aggregate logical limit",
                limits.max_total_logical_bytes
            );
        }
        let allow_torn_tail = ends_namespace && !parsed.is_sealed();
        crate::wal::writer::verify_existing_compaction_marker_windows(
            &logical,
            header_len,
            &verification_keys,
            allow_torn_tail,
        )
        .with_context(|| {
            format!(
                "authenticate compaction-marker windows before scanning {}",
                display.display()
            )
        })?;
        authenticated_segments.push(AuthenticatedHomeSegment {
            namespace: namespace.clone(),
            sequence: *sequence,
            name: name.clone(),
            parsed,
            physical_len,
            physical_sha256_hex,
            logical,
            header_len,
            allow_torn_tail,
        });
    }
    validate_cross_segment_links(&authenticated_segments)
        .context("validate authenticated cross-segment links before full-home callbacks")?;
    for segment in &authenticated_segments {
        scan_one_home_segment(
            &segment.name,
            segment.parsed,
            &segment.logical,
            segment.header_len,
            segment.allow_torn_tail,
            &mut cb,
        )?;
    }
    Ok(())
}

fn canonical_segment_parts(name: &std::ffi::OsStr) -> Option<(Option<&str>, u64)> {
    let name = name.to_str()?;
    let stem = name.strip_suffix(".wal")?;
    let (namespace, sequence) = match stem.rsplit_once('-') {
        Some((namespace, sequence)) => (Some(namespace), sequence),
        None => (None, stem),
    };
    if sequence.len() != 6 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if let Some(namespace) = namespace
        && (namespace.is_empty()
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return None;
    }
    Some((namespace, sequence.parse().ok()?))
}

fn validate_cross_segment_links(segments: &[AuthenticatedHomeSegment]) -> Result<()> {
    for (index, segment) in segments.iter().enumerate() {
        let begins_namespace = index == 0 || segments[index - 1].namespace != segment.namespace;
        anyhow::ensure!(
            !begins_namespace || segment.sequence == 1,
            "WAL namespace {:?} begins at sequence {} without its mandatory predecessor link",
            segment.namespace.as_deref().unwrap_or("<daemon>"),
            segment.sequence
        );
    }
    for pair in segments.windows(2) {
        let predecessor = &pair[0];
        let successor = &pair[1];
        if predecessor.namespace != successor.namespace {
            continue;
        }
        anyhow::ensure!(
            successor.sequence == predecessor.sequence.saturating_add(1),
            "WAL cross-segment link is non-contiguous between sequences {} and {}",
            predecessor.sequence,
            successor.sequence
        );

        let link_frame = decode_frame(
            successor
                .logical
                .get(successor.header_len..)
                .context("successor WAL header exceeds its logical bytes")?,
        )
        .with_context(|| {
            format!(
                "decode mandatory cross-segment link at the head of {}",
                successor.name.to_string_lossy()
            )
        })?;
        anyhow::ensure!(
            link_frame.header.event_type == crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER,
            "WAL successor {} sequence {} does not begin with the mandatory authenticated \
             cross-segment link",
            successor.name.to_string_lossy(),
            successor.sequence
        );
        let link: SegmentRolloverLink =
            serde_json::from_slice(link_frame.payload).with_context(|| {
                format!(
                    "decode cross-segment link in {}",
                    successor.name.to_string_lossy()
                )
            })?;
        let link_end = successor
            .header_len
            .checked_add(link_frame.header.total_len as usize)
            .context("cross-segment link end offset overflow")?;
        let marker_frame = decode_frame(
            successor
                .logical
                .get(link_end..)
                .context("cross-segment link end exceeds successor bytes")?,
        )
        .with_context(|| {
            format!(
                "decode mandatory link-authentication marker in {}",
                successor.name.to_string_lossy()
            )
        })?;
        anyhow::ensure!(
            marker_frame.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            "WAL successor {} cross-segment link is not immediately authenticated by a \
             compaction marker",
            successor.name.to_string_lossy()
        );
        let marker: crate::wal::compaction::MarkerPayload =
            serde_json::from_slice(marker_frame.payload).with_context(|| {
                format!(
                    "decode link-authentication marker in {}",
                    successor.name.to_string_lossy()
                )
            })?;
        anyhow::ensure!(
            marker.from_offset
                == u64::try_from(successor.header_len).context("successor header exceeds u64")?
                && marker.to_offset
                    == u64::try_from(link_end).context("cross-segment link end exceeds u64")?
                && marker.frame_count == 1,
            "WAL successor {} does not authenticate exactly its cross-segment link as the \
             first HMAC window",
            successor.name.to_string_lossy()
        );

        anyhow::ensure!(
            link.link_domain == "neoth.wal.cross-segment.v1" && link.link_version == 1,
            "WAL successor {} has unsupported cross-segment link version {}",
            successor.name.to_string_lossy(),
            link.link_version
        );
        anyhow::ensure!(
            Some(link.closed_segment_name.as_str()) == predecessor.name.to_str()
                && Some(link.opened_segment_name.as_str()) == successor.name.to_str(),
            "WAL successor {} cross-segment link does not bind the canonical chain namespace",
            successor.name.to_string_lossy()
        );
        anyhow::ensure!(
            link.closed_generation == predecessor.parsed.generation()
                && link.closed_seq == predecessor.parsed.segment_seq()
                && link.closed_start_ts_ns == predecessor.parsed.segment_start_ts_ns()
                && link.closed_node_id == predecessor.parsed.node_id(),
            "WAL successor {} cross-segment link does not match predecessor header identity",
            successor.name.to_string_lossy()
        );
        anyhow::ensure!(
            link.closed_bytes
                == u64::try_from(predecessor.logical.len())
                    .context("predecessor logical length exceeds u64")?,
            "WAL successor {} claims predecessor logical length {}, actual {}",
            successor.name.to_string_lossy(),
            link.closed_bytes,
            predecessor.logical.len()
        );
        anyhow::ensure!(
            link.closed_physical_bytes == predecessor.physical_len,
            "WAL successor {} claims predecessor physical length {}, actual {}",
            successor.name.to_string_lossy(),
            link.closed_physical_bytes,
            predecessor.physical_len
        );
        anyhow::ensure!(
            link.closed_sha256_hex == predecessor.physical_sha256_hex,
            "WAL successor {} cross-segment predecessor digest mismatch",
            successor.name.to_string_lossy()
        );
        anyhow::ensure!(
            link.opened_generation == successor.parsed.generation()
                && link.opened_seq == successor.parsed.segment_seq()
                && link.opened_start_ts_ns == successor.parsed.segment_start_ts_ns()
                && link.opened_node_id == successor.parsed.node_id(),
            "WAL successor {} cross-segment link does not match its own header identity",
            successor.name.to_string_lossy()
        );
        anyhow::ensure!(
            matches!(link.reason.as_str(), "size" | "age" | "sealed_restart") && link.ts_ns > 0,
            "WAL successor {} has an invalid cross-segment rotation context",
            successor.name.to_string_lossy()
        );
    }
    Ok(())
}

fn selected_home_chain(
    home: &Path,
    base_segment_path: &Path,
    limits: HomeWalScanLimits,
) -> Result<(crate::skills::store::BoundDirectory, Vec<(u64, OsString)>)> {
    anyhow::ensure!(
        limits.max_segments > 0,
        "selected WAL segment chain has a zero-segment limit"
    );
    let wal_path = std::path::absolute(home.join("wal")).with_context(|| {
        format!(
            "resolve instance WAL directory {}",
            home.join("wal").display()
        )
    })?;
    let base_segment_path = std::path::absolute(base_segment_path)
        .with_context(|| format!("resolve WAL chain base {}", base_segment_path.display()))?;
    let base_name = base_segment_path
        .file_name()
        .context("WAL chain base omitted its file name")?;
    let (base_namespace, base_sequence) = canonical_segment_parts(base_name)
        .context("WAL chain base does not have a canonical segment name")?;
    let base_namespace = base_namespace.map(str::to_owned);
    anyhow::ensure!(
        base_segment_path.parent() == Some(wal_path.as_path()),
        "WAL chain base must be a direct child of {}",
        wal_path.display()
    );

    let root =
        crate::skills::store::open_bound_directory(&wal_path, false, "selected WAL chain root")?
            .with_context(|| {
                format!("selected WAL chain root is missing: {}", wal_path.display())
            })?;
    let mut names = Vec::new();
    let mut gap_seen = false;
    for offset in 0..=limits.max_segments {
        let sequence = base_sequence
            .checked_add(u64::try_from(offset).context("WAL chain offset exceeds u64")?)
            .context("WAL chain sequence overflow")?;
        anyhow::ensure!(
            sequence <= 999_999,
            "WAL chain sequence exceeds the six-digit namespace"
        );
        let name = OsString::from(match base_namespace.as_deref() {
            Some(namespace) => format!("{namespace}-{sequence:06}.wal"),
            None => format!("{sequence:06}.wal"),
        });
        match root.dir.symlink_metadata(&name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                gap_seen = true;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect selected WAL segment {}",
                        root.display_path.join(&name).display()
                    )
                });
            }
            Ok(_) => {
                anyhow::ensure!(
                    !gap_seen,
                    "selected WAL chain is non-contiguous before {}",
                    root.display_path.join(&name).display()
                );
                anyhow::ensure!(
                    offset < limits.max_segments,
                    "selected WAL chain exceeds the {}-segment limit",
                    limits.max_segments
                );
                let display = root.display_path.join(&name);
                let file = crate::skills::store::open_regular_file(&root.dir, &name, &display)
                    .with_context(|| {
                        format!(
                            "selected WAL segment is not a real regular file: {}",
                            display.display()
                        )
                    })?;
                let physical = file
                    .metadata()
                    .with_context(|| format!("inspect selected WAL segment {}", display.display()))?
                    .len();
                anyhow::ensure!(
                    physical <= limits.max_segment_physical_bytes as u64,
                    "selected WAL segment {} exceeds the {}-byte physical limit",
                    display.display(),
                    limits.max_segment_physical_bytes
                );
                use std::io::Read as _;
                let mut header = Vec::with_capacity(super::segment_header::SEGMENT_HEADER_V3_LEN);
                (&file)
                    .take(super::segment_header::SEGMENT_HEADER_V3_LEN as u64)
                    .read_to_end(&mut header)
                    .with_context(|| format!("read selected WAL header {}", display.display()))?;
                let parsed = parse_segment_header(&header)
                    .with_context(|| format!("parse selected WAL header {}", display.display()))?;
                anyhow::ensure!(
                    parsed.segment_seq() == sequence,
                    "selected WAL segment {} header sequence {} differs from file sequence {sequence}",
                    display.display(),
                    parsed.segment_seq()
                );
                names.push((sequence, name));
            }
        }
    }
    Ok((root, names))
}

/// Return the highest existing segment in the selected writer namespace, or
/// the requested base when the chain is new.
///
/// Daemon restarts must resume the last rotated segment. Reopening the literal
/// `000001.wal` after `000002.wal` exists would append newer frames into an
/// older sequence and destroy the chronological recovery contract.
pub(crate) fn latest_home_segment_in_chain(
    home: &Path,
    base_segment_path: &Path,
    limits: HomeWalScanLimits,
) -> Result<std::path::PathBuf> {
    let (root, names) = selected_home_chain(home, base_segment_path, limits)?;
    Ok(names
        .last()
        .map(|(_, name)| root.display_path.join(name))
        .unwrap_or_else(|| base_segment_path.to_path_buf()))
}

/// Walk the complete rotating daemon segment namespace selected by
/// `base_segment_path` without ingesting unrelated WAL-shaped producers.
///
/// Bootstrap, hemisphere, channel and other snapshot writers intentionally use
/// their own files beside the daemon chain. Updater recovery must neither
/// reject nor ingest those independent namespaces. Every selected segment is
/// still opened capability-relative, reconstructed with the instance key and
/// bounded by the same per-segment/aggregate limits as the all-home integrity
/// scanner.
pub(crate) fn for_each_frame_in_home_segment_chain<F>(
    home: &Path,
    base_segment_path: &Path,
    limits: HomeWalScanLimits,
    mut cb: F,
) -> Result<()>
where
    F: FnMut(&HomeWalFrameLocation, &DecodedFrame<'_>) -> Result<()>,
{
    let (root, names) = selected_home_chain(home, base_segment_path, limits)?;
    if names.is_empty() {
        return Ok(());
    }
    let segment_key = load_home_segment_key(&root)?;
    let verification_keys =
        load_home_hmac_keys(home).context("load HMAC keys for authenticated selected WAL scan")?;
    let mut total_physical = 0u64;
    let mut total_logical = 0u64;
    let final_index = names.len().saturating_sub(1);
    let mut authenticated_segments = Vec::with_capacity(names.len());
    for (index, (sequence, name)) in names.into_iter().enumerate() {
        let display = root.display_path.join(&name);
        let raw = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            &name,
            &display,
            limits.max_segment_physical_bytes,
        )
        .with_context(|| {
            format!(
                "read capability-bound selected WAL segment {}",
                display.display()
            )
        })?;
        total_physical = total_physical
            .checked_add(raw.len() as u64)
            .context("selected WAL chain physical-byte counter overflow")?;
        anyhow::ensure!(
            total_physical <= limits.max_total_physical_bytes,
            "selected WAL chain exceeds the {}-byte aggregate physical limit",
            limits.max_total_physical_bytes
        );
        let parsed = parse_segment_header(&raw)
            .with_context(|| format!("parse selected WAL segment header {}", display.display()))?;
        anyhow::ensure!(
            parsed.segment_seq() == sequence,
            "selected WAL segment {} header sequence {} differs from file sequence {sequence}",
            display.display(),
            parsed.segment_seq()
        );
        let (header_len, logical) = logical_segment_bytes_with_key_capped(
            &raw,
            segment_key.as_ref(),
            limits.max_segment_logical_bytes,
        )
        .with_context(|| {
            format!(
                "reconstruct selected home-bound WAL segment {}",
                display.display()
            )
        })?;
        let logical = logical.into_owned();
        let physical_len =
            u64::try_from(raw.len()).context("selected WAL segment physical length exceeds u64")?;
        let physical_sha256_hex = hex::encode(Sha256::digest(&raw));
        total_logical = total_logical
            .checked_add(logical.len() as u64)
            .context("selected WAL chain logical-byte counter overflow")?;
        anyhow::ensure!(
            total_logical <= limits.max_total_logical_bytes,
            "selected WAL chain exceeds the {}-byte aggregate logical limit",
            limits.max_total_logical_bytes
        );
        let allow_torn_tail = index == final_index && !parsed.is_sealed();
        crate::wal::writer::verify_existing_compaction_marker_windows(
            &logical,
            header_len,
            &verification_keys,
            allow_torn_tail,
        )
        .with_context(|| {
            format!(
                "authenticate compaction-marker windows before scanning {}",
                display.display()
            )
        })?;
        let namespace = canonical_segment_parts(&name)
            .context("validated selected WAL name lost its canonical parts")?
            .0
            .map(str::to_owned);
        authenticated_segments.push(AuthenticatedHomeSegment {
            namespace,
            sequence,
            name,
            parsed,
            physical_len,
            physical_sha256_hex,
            logical,
            header_len,
            allow_torn_tail,
        });
    }
    validate_cross_segment_links(&authenticated_segments)
        .context("validate authenticated cross-segment links before selected-chain callbacks")?;
    for segment in &authenticated_segments {
        scan_one_home_segment(
            &segment.name,
            segment.parsed,
            &segment.logical,
            segment.header_len,
            segment.allow_torn_tail,
            &mut cb,
        )?;
    }
    Ok(())
}

/// Resume a selected rotating WAL namespace from an authenticated physical
/// frontier and return the next durable logical frontier.
///
/// Every segment is reconstructed and all cross-segment links are validated
/// before the first recovery callback. The authenticated frontier still
/// controls which frames are replayed; it never permits older chain evidence
/// to escape validation.
pub(crate) fn for_each_frame_in_home_segment_chain_from<F>(
    home: &Path,
    base_segment_path: &Path,
    limits: HomeWalScanLimits,
    frontier: Option<&HomeWalFrontier>,
    mut cb: F,
) -> Result<HomeWalFrontier>
where
    F: FnMut(&HomeWalFrameLocation, &DecodedFrame<'_>) -> Result<()>,
{
    let (root, names) = selected_home_chain(home, base_segment_path, limits)?;
    anyhow::ensure!(
        !names.is_empty(),
        "selected WAL chain has no segment to checkpoint"
    );
    let segment_key = load_home_segment_key(&root)?;
    let verification_keys =
        load_home_hmac_keys(home).context("load HMAC keys for authenticated WAL recovery scan")?;
    let start_index = match frontier {
        Some(frontier) => names
            .iter()
            .position(|(_, name)| name.to_str() == Some(frontier.segment_name.as_str()))
            .context("authenticated updater recovery frontier segment is absent from its chain")?,
        None => 0,
    };
    let mut total_physical = 0u64;
    let mut total_logical = 0u64;
    let final_index = names.len().saturating_sub(1);
    let mut authenticated_segments = Vec::with_capacity(names.len());

    for (index, (sequence, name)) in names.into_iter().enumerate() {
        let display = root.display_path.join(&name);
        let raw = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            &name,
            &display,
            limits.max_segment_physical_bytes,
        )
        .with_context(|| {
            format!(
                "read capability-bound selected WAL tail segment {}",
                display.display()
            )
        })?;
        total_physical = total_physical
            .checked_add(raw.len() as u64)
            .context("selected WAL tail physical-byte counter overflow")?;
        anyhow::ensure!(
            total_physical <= limits.max_total_physical_bytes,
            "selected WAL tail exceeds the {}-byte aggregate physical limit",
            limits.max_total_physical_bytes
        );
        let parsed = parse_segment_header(&raw)
            .with_context(|| format!("parse selected WAL tail header {}", display.display()))?;
        anyhow::ensure!(
            parsed.segment_seq() == sequence,
            "selected WAL tail segment {} header sequence {} differs from file sequence {sequence}",
            display.display(),
            parsed.segment_seq()
        );
        if index == start_index
            && let Some(frontier) = frontier
        {
            anyhow::ensure!(
                frontier.segment_seq == sequence
                    && frontier.segment_generation == parsed.generation()
                    && frontier.segment_start_ts_ns == parsed.segment_start_ts_ns()
                    && frontier.segment_node_id == parsed.node_id(),
                "authenticated updater recovery frontier does not match the on-disk segment header"
            );
        }

        let (header_len, logical) = logical_segment_bytes_with_key_capped(
            &raw,
            segment_key.as_ref(),
            limits.max_segment_logical_bytes,
        )
        .with_context(|| {
            format!(
                "reconstruct selected home-bound WAL tail segment {}",
                display.display()
            )
        })?;
        let logical = logical.into_owned();
        let physical_len =
            u64::try_from(raw.len()).context("selected WAL tail physical length exceeds u64")?;
        let physical_sha256_hex = hex::encode(Sha256::digest(&raw));
        total_logical = total_logical
            .checked_add(logical.len() as u64)
            .context("selected WAL tail logical-byte counter overflow")?;
        anyhow::ensure!(
            total_logical <= limits.max_total_logical_bytes,
            "selected WAL tail exceeds the {}-byte aggregate logical limit",
            limits.max_total_logical_bytes
        );
        let allow_unmarked_tail = index == final_index && !parsed.is_sealed();
        crate::wal::writer::verify_existing_compaction_marker_windows(
            &logical,
            header_len,
            &verification_keys,
            allow_unmarked_tail,
        )
        .with_context(|| {
            format!(
                "authenticate compaction-marker windows before scanning {}",
                display.display()
            )
        })?;
        let namespace = canonical_segment_parts(&name)
            .context("validated recovery WAL name lost its canonical parts")?
            .0
            .map(str::to_owned);
        authenticated_segments.push(AuthenticatedHomeSegment {
            namespace,
            sequence,
            name,
            parsed,
            physical_len,
            physical_sha256_hex,
            logical,
            header_len,
            allow_torn_tail: allow_unmarked_tail,
        });
    }
    validate_cross_segment_links(&authenticated_segments)
        .context("validate authenticated cross-segment links before recovery callbacks")?;

    let mut next_frontier = None;
    for (index, segment) in authenticated_segments.iter().enumerate().skip(start_index) {
        let start_offset = if index == start_index {
            frontier
                .map(|frontier| frontier.next_logical_offset)
                .unwrap_or_else(|| {
                    u64::try_from(segment.header_len).expect("header length fits u64")
                })
        } else {
            u64::try_from(segment.header_len).expect("header length fits u64")
        };
        let start_offset =
            usize::try_from(start_offset).context("WAL recovery frontier offset exceeds usize")?;
        anyhow::ensure!(
            start_offset >= segment.header_len && start_offset <= segment.logical.len(),
            "authenticated updater recovery frontier offset {start_offset} is outside segment {}",
            segment.name.to_string_lossy()
        );
        let mut cursor = start_offset;
        while cursor < segment.logical.len() {
            let frame = match decode_frame(&segment.logical[cursor..]) {
                Ok(frame) => frame,
                Err(super::error::HeaderParseError::BufferTooShort { .. })
                    if segment.allow_torn_tail =>
                {
                    break;
                }
                Err(super::error::HeaderParseError::BufferTooShort { .. }) => {
                    anyhow::bail!(
                        "wal::scan: truncated frame at logical offset {cursor} in sealed \
                         predecessor segment {}",
                        segment.name.to_string_lossy()
                    )
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "wal::scan: tamper-suspect frame at logical offset {cursor}: {error} \
                         (a fully-present frame failed to validate mid-segment — corruption \
                         or tampering, not a torn tail)"
                    ));
                }
            };
            let total = frame.header.total_len as usize;
            anyhow::ensure!(total > 0, "WAL recovery encountered a zero-length frame");
            let location = HomeWalFrameLocation {
                segment_name: segment.name.clone(),
                segment_generation: segment.parsed.generation(),
                segment_seq: segment.parsed.segment_seq(),
                segment_start_ts_ns: segment.parsed.segment_start_ts_ns(),
                segment_node_id: segment.parsed.node_id(),
                logical_offset: u64::try_from(cursor).context("WAL frame offset exceeds u64")?,
            };
            cb(&location, &frame)?;
            cursor = cursor
                .checked_add(total)
                .context("WAL recovery cursor overflow")?;
        }
        next_frontier = Some(HomeWalFrontier {
            segment_name: segment
                .name
                .to_str()
                .context("selected WAL segment name is not UTF-8")?
                .to_string(),
            segment_generation: segment.parsed.generation(),
            segment_seq: segment.parsed.segment_seq(),
            segment_start_ts_ns: segment.parsed.segment_start_ts_ns(),
            segment_node_id: segment.parsed.node_id(),
            next_logical_offset: u64::try_from(cursor)
                .context("WAL recovery frontier offset exceeds u64")?,
        });
    }

    next_frontier.context("selected WAL tail did not produce a recovery frontier")
}

fn scan_one_home_segment<F>(
    name: &OsString,
    parsed: ParsedSegmentHeader,
    logical: &[u8],
    header_len: usize,
    allow_torn_tail: bool,
    cb: &mut F,
) -> Result<()>
where
    F: FnMut(&HomeWalFrameLocation, &DecodedFrame<'_>) -> Result<()>,
{
    for_each_logical_frame(
        logical,
        header_len,
        allow_torn_tail,
        &mut |cursor, frame| {
            let location = HomeWalFrameLocation {
                segment_name: name.clone(),
                segment_generation: parsed.generation(),
                segment_seq: parsed.segment_seq(),
                segment_start_ts_ns: parsed.segment_start_ts_ns(),
                segment_node_id: parsed.node_id(),
                logical_offset: u64::try_from(cursor).context("WAL frame offset exceeds u64")?,
            };
            cb(&location, frame)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::compress::compress_frames;
    use crate::wal::crypto::{encrypt_blob, frame_encrypted};
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::{
        SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SEGMENT_HEADER_V3_LEN, SegmentHeaderV2,
    };
    use std::ffi::OsStr;
    use std::fs;
    use tempfile::tempdir;

    const TEST_HMAC_KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn key_discovery_accepts_every_directory_the_wal_scan_accepts() {
        assert_eq!(
            MAX_HOME_KEY_DIRECTORY_ENTRIES,
            HomeWalScanLimits::default().max_directory_entries
        );
    }

    #[test]
    fn production_full_home_limits_match_the_enforced_writer_quota() {
        let limits = supported_home_scan_limits();
        assert_eq!(
            limits.max_total_physical_bytes,
            crate::daemon::quota::DEFAULT_CEILING_BYTES
        );
        assert_eq!(
            limits.max_total_logical_bytes,
            crate::daemon::quota::DEFAULT_CEILING_BYTES * 2
        );
    }

    #[test]
    fn key_discovery_fails_closed_before_silently_dropping_an_archive() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        fs::create_dir_all(&wal).unwrap();
        fs::write(wal.join("hmac.key"), [7u8; 32]).unwrap();
        for index in 1u8..=65 {
            fs::write(
                wal.join(format!("hmac.key.{:020}.archive", u64::from(index))),
                [index; 32],
            )
            .unwrap();
        }

        let error = load_home_hmac_keys(home.path())
            .expect_err("uncoordinated key pruning must not weaken WAL verification");
        assert!(
            format!("{error:#}").contains(&format!(
                "{}-archive HMAC key limit",
                MAX_HOME_HMAC_ARCHIVES
            )),
            "unexpected error: {error:#}"
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
        uncompressed_segment_with_identity(1, 1, [0u8; 16], frames)
    }

    fn uncompressed_segment_with_identity(
        generation: u32,
        sequence: u64,
        node_id: [u8; 16],
        frames: &[u8],
    ) -> Vec<u8> {
        let hdr = SegmentHeaderV2::new(generation, sequence, 0, 0, node_id, 0);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(frames);
        seg
    }

    fn authenticated_segment_with_identity(
        generation: u32,
        sequence: u64,
        node_id: [u8; 16],
        frames: &[u8],
    ) -> Vec<u8> {
        let mut segment = uncompressed_segment_with_identity(generation, sequence, node_id, frames);
        if frames.is_empty() {
            return segment;
        }
        let header_len = segment.len() - frames.len();
        let mut state =
            crate::wal::compaction::CompactionState::new(&TEST_HMAC_KEY, header_len as u64);
        let mut cursor = 0usize;
        while cursor < frames.len() {
            let frame = decode_frame(&frames[cursor..]).expect("test frame must decode");
            let end = cursor + frame.header.total_len as usize;
            state.update(&frames[cursor..end]);
            cursor = end;
        }
        let marker = state.finalise_marker(&TEST_HMAC_KEY, segment.len() as u64);
        let marker_payload = serde_json::to_vec(&marker).unwrap();
        let marker_header = HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            &marker_payload,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        segment.extend_from_slice(&encode_frame(&marker_header, &marker_payload));
        segment
    }

    fn linked_successor_segment(
        predecessor_name: &str,
        predecessor: &[u8],
        successor_name: &str,
        generation: u32,
        sequence: u64,
        node_id: [u8; 16],
        tail_frames: &[u8],
    ) -> Vec<u8> {
        let predecessor_header = parse_segment_header(predecessor).unwrap();
        let successor_header = SegmentHeaderV2::new(generation, sequence, 0, 0, node_id, 0);
        let mut successor = successor_header.to_le_bytes().to_vec();
        let payload = serde_json::to_vec(&serde_json::json!({
            "link_domain": "neoth.wal.cross-segment.v1",
            "link_version": 1,
            "closed_segment_name": predecessor_name,
            "closed_generation": predecessor_header.generation(),
            "closed_seq": predecessor_header.segment_seq(),
            "closed_bytes": predecessor.len(),
            "closed_start_ts_ns": predecessor_header.segment_start_ts_ns(),
            "closed_node_id": predecessor_header.node_id(),
            "closed_physical_bytes": predecessor.len(),
            "closed_sha256_hex": hex::encode(Sha256::digest(predecessor)),
            "opened_segment_name": successor_name,
            "opened_generation": generation,
            "opened_seq": sequence,
            "opened_start_ts_ns": 0,
            "opened_node_id": node_id,
            "reason": "size",
            "ts_ns": 1,
        }))
        .unwrap();
        let link_header =
            HeaderBuilder::new(crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER, &payload)
                .flags(crate::wal::EventFlags::SYNTHETIC)
                .build();
        let link = encode_frame(&link_header, &payload);
        let header_len = successor.len();
        let mut state =
            crate::wal::compaction::CompactionState::new(&TEST_HMAC_KEY, header_len as u64);
        state.update(&link);
        successor.extend_from_slice(&link);
        let marker = state.finalise_marker(&TEST_HMAC_KEY, successor.len() as u64);
        let marker_payload = serde_json::to_vec(&marker).unwrap();
        let marker_header = HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            &marker_payload,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        successor.extend_from_slice(&encode_frame(&marker_header, &marker_payload));
        successor.extend_from_slice(tail_frames);
        successor
    }

    fn append_authenticated_window(segment: &mut Vec<u8>, frame: &[u8]) {
        let mut state =
            crate::wal::compaction::CompactionState::new(&TEST_HMAC_KEY, segment.len() as u64);
        state.update(frame);
        segment.extend_from_slice(frame);
        let marker = state.finalise_marker(&TEST_HMAC_KEY, segment.len() as u64);
        let marker_payload = serde_json::to_vec(&marker).unwrap();
        let marker_header = HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            &marker_payload,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        segment.extend_from_slice(&encode_frame(&marker_header, &marker_payload));
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
        let hmac_key = wal.join("hmac.key");
        if !hmac_key.exists() {
            fs::write(hmac_key, TEST_HMAC_KEY).unwrap();
        }
        fs::write(wal.join(name), bytes).unwrap();
    }

    fn write_home_hmac_key(home: &Path) {
        let wal = home.join("wal");
        fs::create_dir_all(&wal).unwrap();
        fs::write(wal.join("hmac.key"), TEST_HMAC_KEY).unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_segment_is_scannable_only_after_complete_header_publication() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (prepared, release) = crate::wal::writer::pause_segment_publication_for_test(&segment);
        let (writer, completion) = crate::wal::writer::spawn_for_home_with_completion(
            segment.clone(),
            home.path().to_path_buf(),
        )
        .expect("spawn publication-paused writer");

        tokio::task::spawn_blocking(move || {
            prepared
                .recv_timeout(std::time::Duration::from_secs(15))
                .expect("writer must finish and sync its private header stage");
        })
        .await
        .expect("join publication observer");

        assert!(
            !segment.exists(),
            "canonical WAL name must remain absent until complete-header commit"
        );
        let staged_names: Vec<_> = fs::read_dir(&wal)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            staged_names
                .iter()
                .any(|name| { name.to_string_lossy().starts_with(".neoth-wal-publish-") }),
            "test must observe the private publication stage"
        );
        assert!(
            staged_names
                .iter()
                .all(|name| canonical_segment_parts(name).is_none()),
            "unpublished stage must never enter the canonical scanner namespace"
        );

        let mut limits = HomeWalScanLimits::default();
        limits.max_segments = 8;
        let mut all_home_frames = 0usize;
        for_each_frame_at_home(home.path(), limits, |_, _| {
            all_home_frames += 1;
            Ok(())
        })
        .expect("all-home scanner must ignore an unpublished private stage");
        assert_eq!(all_home_frames, 0);
        let mut selected_frames = 0usize;
        for_each_frame_in_home_segment_chain(home.path(), &segment, limits, |_, _| {
            selected_frames += 1;
            Ok(())
        })
        .expect("selected-chain scanner must see a healthy empty chain before publication");
        assert_eq!(selected_frames, 0);

        release
            .send(())
            .expect("release complete-header publication");
        writer
            .append(
                HeaderBuilder::new(0x31, b"published-frame").build(),
                b"published-frame".to_vec(),
            )
            .await
            .expect("append after publication");
        drop(writer);
        completion.wait().await.expect("complete writer shutdown");

        let mut payloads = Vec::new();
        for_each_frame_at_home(home.path(), limits, |_, frame| {
            payloads.push(frame.payload.to_vec());
            Ok(())
        })
        .expect("published segment must scan cleanly");
        assert!(
            payloads.iter().any(|payload| payload == b"published-frame"),
            "scanner must observe caller frame after atomic publication"
        );
    }

    #[test]
    fn canonical_segment_with_a_corrupt_complete_header_still_fails_closed() {
        let home = tempdir().unwrap();
        let segment = home.path().join("wal/000001.wal");
        write_home_segment(home.path(), "000001.wal", &[0xA5; SEGMENT_HEADER_V3_LEN]);

        let all_home_error =
            for_each_frame_at_home(home.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .expect_err("true canonical-header corruption must fail closed");
        assert!(
            format!("{all_home_error:#}").contains("parse WAL segment header"),
            "{all_home_error:#}"
        );

        let selected_error = for_each_frame_in_home_segment_chain(
            home.path(),
            &segment,
            HomeWalScanLimits::default(),
            |_, _| Ok(()),
        )
        .expect_err("selected-chain scanner must also reject canonical-header corruption");
        assert!(
            format!("{selected_error:#}").contains("parse selected WAL header"),
            "{selected_error:#}"
        );
    }

    #[test]
    fn selected_home_segment_chain_ignores_unrelated_wal_namespaces() {
        let dir = tempdir().unwrap();
        let frame = frame_bytes(0x44, b"daemon-owned");
        let segment = dir.path().join("wal/000001.wal");
        write_home_segment(dir.path(), "000001.wal", &uncompressed_segment(&frame));
        write_home_segment(
            dir.path(),
            "init-snapshot-1700000000.wal",
            b"independent snapshot format",
        );
        write_home_segment(
            dir.path(),
            "hemispheres-snapshot-1700000001.wal",
            b"another independent snapshot format",
        );

        let mut seen = Vec::new();
        for_each_frame_in_home_segment_chain(
            dir.path(),
            &segment,
            HomeWalScanLimits::default(),
            |location, decoded| {
                seen.push((
                    location.segment_name.clone(),
                    decoded.header.event_type,
                    decoded.payload.to_vec(),
                ));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            vec![(OsString::from("000001.wal"), 0x44, b"daemon-owned".to_vec())]
        );

        let all_home_error =
            for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .unwrap_err();
        assert!(
            format!("{all_home_error:#}").contains("non-canonical"),
            "the stricter all-home integrity scanner must retain its existing contract"
        );
    }

    #[test]
    fn selected_home_segment_chain_rejects_paths_outside_the_instance_wal_root() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let segment = outside.path().join("000001.wal");
        fs::write(&segment, uncompressed_segment(&frame_bytes(0x01, b"x"))).unwrap();

        let error = for_each_frame_in_home_segment_chain(
            dir.path(),
            &segment,
            HomeWalScanLimits::default(),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("direct child"));
    }

    #[test]
    fn authenticated_frontier_resumes_only_the_cross_rotation_tail() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("wal/000001.wal");
        let predecessor =
            authenticated_segment_with_identity(7, 1, [1u8; 16], &frame_bytes(0x31, b"first"));
        let successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &frame_bytes(0x32, b"second"),
        );
        write_home_segment(dir.path(), "000001.wal", &predecessor);
        write_home_segment(dir.path(), "000002.wal", &successor);
        let mut first = Vec::new();
        let frontier = for_each_frame_in_home_segment_chain_from(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            None,
            |location, frame| {
                if frame.header.event_type != crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
                    first.push((location.segment_seq, frame.payload.to_vec()));
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(first.contains(&(1, b"first".to_vec())));
        assert!(first.contains(&(2, b"second".to_vec())));
        assert_eq!(frontier.segment_name, "000002.wal");

        let mut second_bytes = fs::read(dir.path().join("wal/000002.wal")).unwrap();
        second_bytes.extend_from_slice(&frame_bytes(0x33, b"third"));
        fs::write(dir.path().join("wal/000002.wal"), second_bytes).unwrap();
        let mut resumed = Vec::new();
        let advanced = for_each_frame_in_home_segment_chain_from(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            Some(&frontier),
            |location, frame| {
                resumed.push((location.segment_seq, frame.payload.to_vec()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(resumed, vec![(2, b"third".to_vec())]);
        assert!(advanced.next_logical_offset > frontier.next_logical_offset);

        let mut mismatched = advanced;
        mismatched.segment_generation += 1;
        let error = for_each_frame_in_home_segment_chain_from(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            Some(&mismatched),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("does not match the on-disk segment header"));
    }

    #[test]
    fn marker_covered_updater_tamper_fails_before_every_home_callback() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("wal/000001.wal");
        let payload = b"updater-intent";
        let updater_header = HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, payload)
            .event_subtype(crate::wal::events::ExtendedSubtype::UpdaterLeafIntent as u8)
            .build();
        let updater_frame = encode_frame(&updater_header, payload);
        let mut predecessor = authenticated_segment_with_identity(7, 1, [1u8; 16], &updater_frame);

        let frame_start = SEGMENT_HEADER_V2_LEN;
        let payload_offset = frame_start + 4 + 96;
        predecessor[payload_offset] ^= 0x01;
        let crc_offset = frame_start + updater_frame.len() - 4;
        let crc = crc32c::crc32c(&predecessor[frame_start..crc_offset]);
        predecessor[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        decode_frame(&predecessor[frame_start..])
            .expect("tampered updater frame must retain a valid public CRC");

        let successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &[],
        );
        write_home_segment(dir.path(), "000001.wal", &predecessor);
        write_home_segment(dir.path(), "000002.wal", &successor);

        let mut all_home_callbacks = 0usize;
        let all_home_error =
            for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| {
                all_home_callbacks += 1;
                Ok(())
            })
            .expect_err("full-home scanner must reject stale marker HMAC");
        assert_eq!(all_home_callbacks, 0);
        assert!(
            format!("{all_home_error:#}").contains("did not verify"),
            "{all_home_error:#}"
        );

        let mut selected_callbacks = 0usize;
        let selected_error = for_each_frame_in_home_segment_chain(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                selected_callbacks += 1;
                Ok(())
            },
        )
        .expect_err("selected full-chain scanner must reject stale marker HMAC");
        assert_eq!(selected_callbacks, 0);
        assert!(
            format!("{selected_error:#}").contains("did not verify"),
            "{selected_error:#}"
        );

        let mut frontier_callbacks = 0usize;
        let frontier_error = for_each_frame_in_home_segment_chain_from(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            None,
            |_, _| {
                frontier_callbacks += 1;
                Ok(())
            },
        )
        .expect_err("frontier scanner must reject stale marker HMAC");
        assert_eq!(frontier_callbacks, 0);
        assert!(
            format!("{frontier_error:#}").contains("did not verify"),
            "{frontier_error:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn header_only_predecessor_truncation_fails_all_scanners_before_callbacks() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        fs::create_dir(&wal).unwrap();
        let base = wal.join("000001.wal");
        let policy = crate::wal::writer::RotationPolicy {
            max_bytes: 200,
            max_age_ns: crate::wal::writer::RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        let (writer, join, ready) = crate::wal::writer::spawn_for_home_with_policy_ready(
            base.clone(),
            home.path().to_path_buf(),
            policy,
        )
        .unwrap();
        ready.wait().await.unwrap();

        let authority = b"updater-authority";
        writer
            .append(
                HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, authority)
                    .event_subtype(crate::wal::events::ExtendedSubtype::UpdaterLeafIntent as u8)
                    .build(),
                authority.to_vec(),
            )
            .await
            .unwrap();
        writer
            .append(
                HeaderBuilder::new(0x31, b"successor-frame").build(),
                b"successor-frame".to_vec(),
            )
            .await
            .unwrap();
        drop(writer);
        join.await.unwrap().unwrap();

        let predecessor = fs::read(&base).unwrap();
        let header_len = parse_segment_header(&predecessor).unwrap().header_len();
        fs::write(&base, &predecessor[..header_len]).unwrap();
        assert!(wal.join("000002.wal").is_file());

        let mut all_callbacks = 0usize;
        let all_error =
            for_each_frame_at_home(home.path(), HomeWalScanLimits::default(), |_, _| {
                all_callbacks += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(all_callbacks, 0);
        let all_message = format!("{all_error:#}");
        assert!(
            all_message.contains("logical length")
                || all_message.contains("physical length")
                || all_message.contains("digest mismatch"),
            "{all_error:#}"
        );

        let mut selected_callbacks = 0usize;
        let selected_error = for_each_frame_in_home_segment_chain(
            home.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                selected_callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(selected_callbacks, 0);
        let selected_message = format!("{selected_error:#}");
        assert!(
            selected_message.contains("logical length")
                || selected_message.contains("physical length")
                || selected_message.contains("digest mismatch"),
            "{selected_error:#}"
        );

        let mut frontier_callbacks = 0usize;
        let frontier_error = for_each_frame_in_home_segment_chain_from(
            home.path(),
            &base,
            HomeWalScanLimits::default(),
            None,
            |_, _| {
                frontier_callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(frontier_callbacks, 0);
        let frontier_message = format!("{frontier_error:#}");
        assert!(
            frontier_message.contains("logical length")
                || frontier_message.contains("physical length")
                || frontier_message.contains("digest mismatch"),
            "{frontier_error:#}"
        );
    }

    #[test]
    fn transplanted_cross_segment_namespace_fails_before_callbacks() {
        let home = tempdir().unwrap();
        let predecessor =
            authenticated_segment_with_identity(7, 1, [1u8; 16], &frame_bytes(0x31, b"first"));
        let successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &[],
        );
        write_home_segment(home.path(), "audit-000001.wal", &predecessor);
        write_home_segment(home.path(), "audit-000002.wal", &successor);

        let mut callbacks = 0usize;
        let error = for_each_frame_at_home(home.path(), HomeWalScanLimits::default(), |_, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(format!("{error:#}").contains("canonical chain namespace"));
    }

    #[test]
    fn successor_link_without_immediate_marker_fails_before_callbacks() {
        let home = tempdir().unwrap();
        let base = home.path().join("wal/000001.wal");
        let predecessor =
            authenticated_segment_with_identity(7, 1, [1u8; 16], &frame_bytes(0x31, b"first"));
        let mut successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &[],
        );
        let link = decode_frame(&successor[SEGMENT_HEADER_V2_LEN..]).unwrap();
        successor.truncate(SEGMENT_HEADER_V2_LEN + link.header.total_len as usize);
        write_home_segment(home.path(), "000001.wal", &predecessor);
        write_home_segment(home.path(), "000002.wal", &successor);

        let mut callbacks = 0usize;
        let error = for_each_frame_in_home_segment_chain(
            home.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(format!("{error:#}").contains("link-authentication marker"));

        let startup_error = match crate::wal::writer::spawn_for_home_ready(
            home.path().join("wal/000002.wal"),
            home.path().to_path_buf(),
        ) {
            Ok(_) => {
                panic!("writer startup must not append to a successor without its link marker")
            }
            Err(error) => error,
        };
        assert!(
            format!("{startup_error:#}").contains("link-authentication marker"),
            "{startup_error:#}"
        );
    }

    #[test]
    fn predecessor_truncated_to_an_earlier_valid_marker_fails_before_callbacks() {
        let home = tempdir().unwrap();
        let base = home.path().join("wal/000001.wal");
        let mut predecessor = uncompressed_segment_with_identity(7, 1, [1u8; 16], &[]);
        append_authenticated_window(&mut predecessor, &frame_bytes(0x31, b"first-window"));
        let earlier_marker_end = predecessor.len();
        append_authenticated_window(&mut predecessor, &frame_bytes(0x32, b"second-window"));
        let successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &[],
        );
        predecessor.truncate(earlier_marker_end);
        write_home_segment(home.path(), "000001.wal", &predecessor);
        write_home_segment(home.path(), "000002.wal", &successor);

        let mut callbacks = 0usize;
        let error = for_each_frame_in_home_segment_chain(
            home.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(callbacks, 0);
        let message = format!("{error:#}");
        assert!(
            message.contains("logical length")
                || message.contains("physical length")
                || message.contains("digest mismatch"),
            "{error:#}"
        );
    }

    #[test]
    fn public_crc_recomputed_link_tamper_fails_hmac_before_callbacks() {
        let home = tempdir().unwrap();
        let base = home.path().join("wal/000001.wal");
        let predecessor =
            authenticated_segment_with_identity(7, 1, [1u8; 16], &frame_bytes(0x31, b"first"));
        let mut successor = linked_successor_segment(
            "000001.wal",
            &predecessor,
            "000002.wal",
            7,
            2,
            [1u8; 16],
            &[],
        );
        let frame_start = SEGMENT_HEADER_V2_LEN;
        let link = decode_frame(&successor[frame_start..]).unwrap();
        let link_header_len = usize::from(link.header.header_len);
        let link_total_len = link.header.total_len as usize;
        let payload_start = frame_start + 4 + link_header_len;
        let reason = b"\"reason\":\"size\"";
        let reason_offset = successor[payload_start..]
            .windows(reason.len())
            .position(|window| window == reason)
            .unwrap();
        successor[payload_start + reason_offset + b"\"reason\":\"".len()] = b'z';
        let crc_offset = frame_start + link_total_len - 4;
        let crc = crc32c::crc32c(&successor[frame_start..crc_offset]);
        successor[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        decode_frame(&successor[frame_start..])
            .expect("tampered link must retain a valid public CRC");

        write_home_segment(home.path(), "000001.wal", &predecessor);
        write_home_segment(home.path(), "000002.wal", &successor);
        let mut callbacks = 0usize;
        let error = for_each_frame_in_home_segment_chain(
            home.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(format!("{error:#}").contains("did not verify"));
    }

    #[test]
    fn truncated_predecessor_in_selected_chain_fails_closed() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("wal/000001.wal");
        let mut predecessor =
            uncompressed_segment_with_identity(7, 1, [1u8; 16], &frame_bytes(0x31, b"durable"));
        predecessor.extend_from_slice(&frame_bytes(0x32, b"truncated")[..17]);
        write_home_segment(dir.path(), "000001.wal", &predecessor);
        write_home_segment(
            dir.path(),
            "000002.wal",
            &uncompressed_segment_with_identity(7, 2, [1u8; 16], &frame_bytes(0x33, b"later")),
        );

        let complete_error = for_each_frame_in_home_segment_chain(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(
            format!("{complete_error:#}").contains("buffer too short"),
            "{complete_error:#}"
        );

        let tail_error = for_each_frame_in_home_segment_chain_from(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            None,
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(
            format!("{tail_error:#}").contains("buffer too short"),
            "{tail_error:#}"
        );
    }

    #[test]
    fn all_home_scan_fails_closed_on_truncated_namespace_predecessor() {
        let dir = tempdir().unwrap();
        let mut predecessor =
            uncompressed_segment_with_identity(9, 1, [3u8; 16], &frame_bytes(0x31, b"durable"));
        predecessor.extend_from_slice(&frame_bytes(0x32, b"truncated")[..17]);
        write_home_segment(dir.path(), "audit-000001.wal", &predecessor);
        write_home_segment(
            dir.path(),
            "audit-000002.wal",
            &uncompressed_segment_with_identity(9, 2, [3u8; 16], &frame_bytes(0x33, b"later")),
        );

        let error = for_each_frame_at_home(dir.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("buffer too short"),
            "{error:#}"
        );
    }

    #[test]
    fn all_home_scan_binds_filename_order_to_header_sequence_and_contiguity() {
        let mismatch = tempdir().unwrap();
        write_home_segment(
            mismatch.path(),
            "audit-000001.wal",
            &uncompressed_segment_with_identity(1, 2, [0u8; 16], &frame_bytes(0x31, b"x")),
        );
        let error =
            for_each_frame_at_home(mismatch.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("differs from file sequence"),
            "{error:#}"
        );

        let gap = tempdir().unwrap();
        write_home_segment(
            gap.path(),
            "audit-000001.wal",
            &uncompressed_segment_with_identity(1, 1, [0u8; 16], &frame_bytes(0x31, b"x")),
        );
        write_home_segment(
            gap.path(),
            "audit-000003.wal",
            &uncompressed_segment_with_identity(1, 3, [0u8; 16], &frame_bytes(0x33, b"z")),
        );
        let error = for_each_frame_at_home(gap.path(), HomeWalScanLimits::default(), |_, _| Ok(()))
            .unwrap_err();
        assert!(format!("{error:#}").contains("non-contiguous"), "{error:#}");
    }

    #[test]
    fn legacy_maximum_segment_remains_within_the_recovery_ceiling() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("wal/000001.wal");
        let header_len = SEGMENT_HEADER_V2_LEN;
        let first_payload_len = LEGACY_ROTATION_TARGET_BYTES - header_len - 104 - 1;
        let first_payload = vec![0x11; first_payload_len];
        let second_payload = vec![0x22; 16 * 1024 * 1024];
        let mut frames = frame_bytes(0x31, &first_payload);
        frames.extend_from_slice(&frame_bytes(0x32, &second_payload));
        let segment = uncompressed_segment_with_identity(1, 1, [0u8; 16], &frames);
        assert!(segment.len() > 32 * 1024 * 1024);
        assert!(segment.len() <= LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES);
        write_home_segment(dir.path(), "000001.wal", &segment);

        let mut seen = 0usize;
        for_each_frame_in_home_segment_chain(
            dir.path(),
            &base,
            HomeWalScanLimits::default(),
            |_, _| {
                seen += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, 2);

        let mut too_small = HomeWalScanLimits::default();
        too_small.max_segment_physical_bytes = segment.len() - 1;
        let error = latest_home_segment_in_chain(dir.path(), &base, too_small).unwrap_err();
        assert!(format!("{error:#}").contains("physical limit"));
    }

    #[test]
    fn latest_chain_discovery_ignores_lifetime_aggregate_payload_limit() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("wal/000001.wal");
        for sequence in 1..=64 {
            write_home_segment(
                dir.path(),
                &format!("{sequence:06}.wal"),
                &uncompressed_segment_with_identity(4, sequence, [9u8; 16], &[]),
            );
        }
        let mut limits = HomeWalScanLimits::default();
        limits.max_total_physical_bytes = 1;
        let latest = latest_home_segment_in_chain(dir.path(), &base, limits).unwrap();
        assert_eq!(
            latest.file_name().and_then(OsStr::to_str),
            Some("000064.wal")
        );
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
