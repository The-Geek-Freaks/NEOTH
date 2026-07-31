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
//!   3. For a *sealed compressed* (v2/zstd) segment, whose frames live inside
//!      a single zstd blob and so can't be reached by in-place overwrite:
//!      decompressing into logical frame space, redacting matches there (same
//!      zero-payload + `REDACTED` + CRC recompute), recompressing, and
//!      atomically replacing the file with the header preserved byte-for-byte
//!      (GOLD-ARCH-03b — `redact_sealed_compressed_segment`).
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
//!   - Installed-Skill mutation and authority proof frames are categorically
//!     non-redactable. Their authenticated payloads are live authorization
//!     inputs, not memory content; erasing one would silently invalidate the
//!     installed runtime authority chain.
//!   - Segments containing authenticated chain-structural frames
//!     (`COMPACTION_MARKER`, `SEGMENT_ROLLOVER`, or `REDACTION_MARKER`) are not
//!     physically rewritten. Their offsets and authenticated links require a
//!     dedicated transaction that can replace the chain evidence atomically.
//!   - Every original frame CRC validates before predicates or redaction run;
//!     the eraser never converts pre-existing corruption into a newly valid
//!     redacted frame.
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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions as CapOpenOptions;

use super::header::{CRC_LEN, EventHeaderV2, HEADER_BODY_LEN, MAGIC, PREAMBLE_LEN};
use super::segment_header::{SEGMENT_HEADER_LEN, SEGMENT_HEADER_V3_LEN, parse_segment_header};
use super::types::EventFlags;

/// Byte offset of the `flags` field WITHIN the header body (after the preamble).
/// Both redaction paths flip the `REDACTED` bit at `frame_start + PREAMBLE_LEN +
/// FLAGS_OFFSET_IN_HEADER_BODY`. Single source of truth so the two sites can't
/// drift if the header layout ever changes (see `EventHeaderV2` field order).
const FLAGS_OFFSET_IN_HEADER_BODY: usize = 4;

fn is_installed_skill_runtime_proof(header: &EventHeaderV2) -> bool {
    if header.event_type != super::events::EVENT_TYPE_EXTENDED {
        return false;
    }
    matches!(
        super::events::ExtendedSubtype::from_u8(header.event_subtype),
        Some(
            super::events::ExtendedSubtype::SkillInstallIntent
                | super::events::ExtendedSubtype::SkillInstallResult
                | super::events::ExtendedSubtype::SkillRemovalIntent
                | super::events::ExtendedSubtype::SkillRemovalResult
                | super::events::ExtendedSubtype::SkillAuthorityDecision
        )
    )
}

fn is_authenticated_chain_structure(header: &EventHeaderV2) -> bool {
    matches!(
        header.event_type,
        super::events::EVENT_TYPE_COMPACTION_MARKER
            | super::events::EVENT_TYPE_SEGMENT_ROLLOVER
            | super::events::EVENT_TYPE_REDACTION_MARKER
    )
}

#[derive(Debug, Default)]
struct StagedRedaction {
    report: RedactReport,
    contains_authenticated_chain_structure: bool,
    matched_authenticated_chain_structure: bool,
}

fn refuse_chain_structural_rewrite(segment_path: &Path, staged: &StagedRedaction) -> Result<()> {
    let has_physical_match =
        !staged.report.frames_redacted.is_empty() || staged.matched_authenticated_chain_structure;
    if staged.contains_authenticated_chain_structure && has_physical_match {
        anyhow::bail!(
            "wal::redact: refusing physical redaction of segment {} because it contains \
             authenticated chain-structural frames (COMPACTION_MARKER, \
             SEGMENT_ROLLOVER/cross-link, or REDACTION_MARKER); physical redaction awaits an \
             authenticated rewrite transaction; logical forget is still usable",
            segment_path.display()
        );
    }
    Ok(())
}

/// Stable sibling lock shared by the WAL writer and physical redactors.
///
/// Locking the segment file itself is not sufficient: both redaction paths
/// atomically replace that inode, while a writer on Unix can keep appending to
/// the unlinked predecessor. The sidecar identity survives replacement and is
/// therefore the one exclusion point for the complete segment lifecycle.
pub(crate) fn segment_rewrite_lock_path(segment_path: &Path) -> PathBuf {
    let mut lock_path = segment_path.as_os_str().to_os_string();
    lock_path.push(".rewrite.lock");
    PathBuf::from(lock_path)
}

/// Acquire exclusive ownership of a WAL segment's bytes.
///
/// The writer holds this guard from before its first open until the segment is
/// durably closed/rotated. A redactor holds it from before its snapshot read
/// through tmp fsync, atomic replacement, and the platform namespace-durability
/// barrier. This closes both append-vs-replace data loss and concurrent-redactor
/// resurrection.
pub(crate) fn lock_segment_for_rewrite(segment_path: &Path) -> Result<std::fs::File> {
    let lock_path = segment_rewrite_lock_path(segment_path);
    let started = std::time::Instant::now();
    loop {
        if let Some(file) = try_lock_segment_rewrite_once(&lock_path)? {
            return Ok(file);
        }
        if started.elapsed() >= std::time::Duration::from_secs(5) {
            anyhow::bail!(
                "WAL segment rewrite lock {} held by another process for >5s",
                lock_path.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn try_lock_segment_rewrite_once(lock_path: &Path) -> Result<Option<std::fs::File>> {
    let parent = lock_path
        .parent()
        .context("WAL rewrite lock omitted its parent")?;
    let name = lock_path
        .file_name()
        .context("WAL rewrite lock omitted its file name")?;
    let root =
        crate::skills::store::open_bound_directory(parent, false, "WAL rewrite lock parent")?
            .with_context(|| format!("WAL rewrite lock parent is missing: {}", parent.display()))?;
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_READ, READ_CONTROL, WRITE_DAC,
        };
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
    }
    let file = match root.dir.open_with(name, &options) {
        Ok(file) => file,
        #[cfg(windows)]
        Err(error) if error.raw_os_error() == Some(32) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "open capability-bound WAL rewrite lock {}",
                    lock_path.display()
                )
            });
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect WAL rewrite lock {}", lock_path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !crate::skills::store::cap_metadata_is_link_like(&metadata),
        "WAL rewrite lock must be a real regular file without links: {}",
        lock_path.display()
    );
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        use std::os::unix::io::AsRawFd as _;
        file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
        let file = file.into_std();
        // SAFETY: `file` owns a valid descriptor for the exact no-follow leaf.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        Err(error).with_context(|| format!("flock {}", lock_path.display()))
    }
    #[cfg(windows)]
    {
        let file = file.into_std();
        super::win_native::set_private_current_user_file_handle_dacl(&file)?;
        Ok(Some(file))
    }
}

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
/// overwritten. Installed-Skill mutation/authority proofs are not memory
/// content and cannot be redacted: if the predicate matches one, this returns
/// an error before any replacement reaches disk. Wrap the predicate carefully:
/// a panic aborts the scan, but the original segment remains byte-identical
/// because all frame edits are staged in memory and committed atomically only
/// after the complete walk succeeds.
pub fn scan_and_redact<F>(segment_path: &Path, mut predicate: F) -> Result<RedactReport>
where
    F: FnMut(&[u8]) -> bool,
{
    // P1 concurrency boundary: take the stable sidecar lock BEFORE the first
    // open/stat/snapshot and retain it until this function returns. In the
    // rewrite case that is after tmp fsync + rename + the platform namespace
    // durability barrier. The WAL writer takes the same lock for the active
    // segment's entire lifecycle.
    // Consequently a redactor can never replace underneath an appending writer,
    // and a second redactor cannot publish a stale snapshot that resurrects
    // payloads scrubbed by the first.
    let _segment_rewrite_guard = lock_segment_for_rewrite(segment_path).with_context(|| {
        format!(
            "cannot exclusively redact WAL segment {} — an active writer holds this lock until \
             rotation/shutdown, or another redaction is still completing; retry after it releases",
            segment_path.display()
        )
    })?;

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
    // apart: we peek the body for a frame MAGIC. Raw frames ⇒ redact in place;
    // a zstd blob ⇒ take the GOLD-ARCH-03b decompress → redact-in-logical-space
    // → recompress → atomic-rewrite path (`redact_sealed_compressed_segment`).
    // Either way a predicate match is physically scrubbed — never a silent
    // no-op (the caller, `memory::forget`, reports success, so a silent skip
    // would be a privacy hole).
    let (header_len, sealed_compressed) = {
        // WS-BUG P0: probe the WIDEST header (v3 = 65 B) so parse_segment_header
        // can identify a v3 segment — the active writer format. The old
        // `SEGMENT_HEADER_LEN + 1` (61) starved the v3 parse (needs 65), so it
        // returned UnknownFormat{3} and forget --physical bailed "tamper-suspect"
        // on every current segment, leaving GDPR physical redaction non-functional.
        let probe_len = SEGMENT_HEADER_V3_LEN.min(file_len as usize);
        let mut probe = vec![0u8; probe_len];
        file.seek(SeekFrom::Start(0))
            .context("seek to segment head")?;
        file.read_exact(&mut probe).context("read segment head")?;
        match parse_segment_header(&probe) {
            Ok(h) => {
                let hl = h.header_len() as u64;
                let mut sealed = false;
                if h.is_compressed() && file_len > hl {
                    let mut magic = [0u8; PREAMBLE_LEN];
                    file.seek(SeekFrom::Start(hl)).context("seek to body")?;
                    // A zstd blob body (first bytes are NOT a frame preamble) is
                    // a *finalised* compressed segment → route to the
                    // decompress/recompress rewrite path below. A raw-frame body
                    // (magic matches) is a *live* v2 segment → redact in place.
                    if file.read_exact(&mut magic).is_ok() && magic != MAGIC {
                        sealed = true;
                    }
                }
                (hl, sealed)
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
                (SEGMENT_HEADER_LEN as u64, false)
            }
        }
    };

    // GOLD-ARCH-03b — sealed compressed segment: the in-place seek+overwrite
    // loop can't touch frames inside a zstd blob. Close the r/w handle first
    // (Windows refuses to rename over a file that still has an open handle),
    // then hand off to the decompress → redact → recompress → atomic-rewrite
    // path. It preserves the 61-byte segment header byte-for-byte, so the file
    // stays a valid compressed v2 segment and downstream readers / `neoth
    // verify` reconstruct it identically.
    if sealed_compressed {
        drop(file);
        return redact_sealed_compressed_segment(segment_path, header_len as usize, predicate);
    }

    // Live (uncompressed) segment — crash-consistent whole-segment rewrite.
    //
    // The old per-frame in-place approach (zero payload + flip flag + recompute
    // CRC, three separate seek+write calls per frame, fsync between each pair)
    // was NOT crash-consistent: a power loss between any two writes left a frame
    // with an inconsistent CRC / partial payload zero.  With no recovery record
    // a GDPR "data is gone" claim was false.
    //
    // New path mirrors the sealed-compressed path (GOLD-ARCH-03b):
    //   read entire segment → redact matching frames in an in-memory buffer →
    //   write unique owner-private tmp → fsync tmp → atomic rename over original
    //   → fsync parent dir.
    // A crash before the rename leaves the original untouched; a crash after
    // rename leaves the fully-redacted file.  The `.redact.tmp` is cleaned up
    // on any error path.
    //
    // Close the r/w handle BEFORE reading: Windows refuses to rename over a file
    // that still has an open handle, and we must not hold it across the rename.
    drop(file);

    let file_bytes = std::fs::read(segment_path)
        .with_context(|| format!("read live WAL segment {}", segment_path.display()))?;

    let hlen = header_len as usize;
    // Defensive: file could have shrunk between the probe and now (very unlikely
    // but would panic on slice indexing otherwise).
    if hlen > file_bytes.len() {
        anyhow::bail!(
            "live WAL segment {} shrank below its own header length between open and read",
            segment_path.display()
        );
    }
    let seg_header_bytes = file_bytes[..hlen].to_vec();
    let mut frames = file_bytes[hlen..].to_vec();

    // `allow_torn_tail: true` — a live segment may have a partial last frame
    // from an unclean shutdown; the buffer walker treats it as end-of-frames
    // (break) rather than corruption (bail).
    let staged = redact_frames_in_buffer(
        &mut frames,
        &mut predicate,
        header_len,
        segment_path,
        /* allow_torn_tail = */ true,
    )?;
    refuse_chain_structural_rewrite(segment_path, &staged)?;
    let report = staged.report;

    // No match ⇒ leave the file byte-identical; no rewrite needed.
    if report.frames_redacted.is_empty() {
        return Ok(report);
    }

    // Concurrent-writer guard: if the live WAL writer appended frames between
    // our snapshot read and this rename, the rename would silently DROP those
    // frames (on Unix the writer's fd keeps pointing at the orphaned inode).
    // Windows already fails the rename loudly while the writer holds the
    // handle; this size check gives Unix the same fail-closed behaviour.
    // Operational contract: `memory::forget --physical` on the LIVE segment
    // requires the daemon to be stopped or the segment rotated first.
    let size_now = std::fs::metadata(segment_path)
        .with_context(|| format!("re-stat live WAL segment {}", segment_path.display()))?
        .len();
    if size_now != file_bytes.len() as u64 {
        anyhow::bail!(
            "live WAL segment {} grew during redaction ({} -> {} bytes) — a writer is \
             appending; stop the daemon or rotate the segment, then re-run forget",
            segment_path.display(),
            file_bytes.len(),
            size_now
        );
    }

    // At least one frame was redacted in the buffer.  Atomically replace the
    // segment: write tmp → fsync → rename → parent fsync.
    write_tmp_and_rename(segment_path, &seg_header_bytes, &frames)?;
    Ok(report)
}

/// Atomically replace `segment_path` with `header_bytes ++ body`:
/// write to a unique owner-private `.redact.tmp`, fsync, then durably replace
/// the original. Unix commits the renamed directory entry with a mandatory
/// parent-directory fsync; Windows uses `MoveFileExW` with both
/// `MOVEFILE_REPLACE_EXISTING` and `MOVEFILE_WRITE_THROUGH`.
///
/// Used by both the live-segment and sealed-compressed redaction paths so
/// the crash-consistency contract is enforced in one place.  A
/// PER-INVOCATION unique tmp name (`{stem}.{pid}.{seq}.redact.tmp`) stops
/// a second concurrent redaction of the same segment from clobbering this
/// one's tmp mid-write.  On any error the temp file is removed so the
/// original segment is left untouched.
fn write_tmp_and_rename(segment_path: &Path, header_bytes: &[u8], body: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static REDACT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = REDACT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        "{}.{}.{}.redact.tmp",
        segment_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "segment".to_string()),
        std::process::id(),
        seq
    );
    let tmp_path = segment_path.with_file_name(tmp_name);
    {
        let mut tmp_opts = std::fs::OpenOptions::new();
        tmp_opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            tmp_opts.mode(0o600);
        }
        let mut tmp = tmp_opts
            .open(&tmp_path)
            .with_context(|| format!("open redact tmp {}", tmp_path.display()))?;
        tmp.write_all(header_bytes)
            .context("write preserved segment header to redact tmp")?;
        tmp.write_all(body)
            .context("write redacted body to redact tmp")?;
        tmp.sync_all().context("fsync redact tmp")?;
    } // handle dropped here — closed before rename (required on Windows)
    if let Err(e) = durable_replace(&tmp_path, segment_path) {
        // Before replacement the original is untouched. If the namespace
        // durability step fails after Unix rename, the redacted target stays
        // in place but the caller still fails closed and emits no success
        // marker because crash persistence is unconfirmed.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::Error::new(e).context(format!(
            "durably replace redacted segment over {}",
            segment_path.display()
        )));
    }
    Ok(())
}

/// Commit an already-fsynced sibling over `target` without a crash window.
///
/// A successful return is the boundary after which the caller may emit its
/// `REDACTION_MARKER`. Namespace-durability errors therefore propagate even
/// when the replacement itself already landed: reporting an incomplete
/// erasure is safer than claiming a rename that a power loss could undo.
fn durable_replace(staged: &Path, target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let staged_wide = staged
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let target_wide = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for
        // the call; `staged` is a sibling of `target`, so this is a same-volume
        // atomic replacement rather than the API's copy/delete fallback.
        if unsafe {
            MoveFileExW(
                staged_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(staged, target)?;
        #[cfg(unix)]
        if let Some(parent) = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }

    Ok(())
}

/// GOLD-ARCH-03b — redact a *sealed compressed* (v2/zstd) segment.
///
/// A finalised compressed segment's frames live inside a single zstd blob, so
/// the in-place seek+overwrite path can't reach them. This decompresses the
/// blob into logical frame space, redacts matching frames there (zero payload +
/// `REDACTED` flag + recomputed CRC — exactly like the on-disk path), then
/// recompresses and atomically replaces the file. The 61-byte segment header is
/// preserved verbatim, so generation / seq / first_event_id / node_id / flags
/// (still `COMPRESSED`) are unchanged and the file stays a valid v2 segment.
///
/// `frames_redacted` in the report are recorded as **logical-segment offsets**
/// (`header_len + position_in_decompressed_body`) — the SAME coordinate space
/// `neoth verify` uses when it reconstructs the segment via
/// [`crate::wal::compaction::logical_segment_bytes`]. That alignment is what
/// lets an operator-signed `0xF3 REDACTION_MARKER` reclassify the resulting
/// compaction-marker HMAC mismatch as authorised instead of a bogus FAIL.
fn redact_sealed_compressed_segment<F>(
    segment_path: &Path,
    header_len: usize,
    mut predicate: F,
) -> Result<RedactReport>
where
    F: FnMut(&[u8]) -> bool,
{
    use super::compress::{compress_frames, decompress_frames};

    let file_bytes = std::fs::read(segment_path)
        .with_context(|| format!("read compressed WAL segment {}", segment_path.display()))?;
    // The header is kept byte-for-byte; only the zstd body is rewritten.
    let header_bytes = file_bytes[..header_len].to_vec();
    let blob = &file_bytes[header_len..];
    // GOLD-ADAPT-CRYPTO-04f — a sealed segment may be AEAD-encrypted-on-seal.
    // Decrypt the body (the plaintext header is the AAD) BEFORE decompressing,
    // and remember so the rewrite RE-ENCRYPTS — never downgrade an encrypted
    // segment to plaintext via a redaction.
    let was_encrypted = super::crypto::is_encrypted(blob);
    let compressed_blob: std::borrow::Cow<'_, [u8]> = if was_encrypted {
        let key = super::master_key::default_segment_key().ok_or_else(|| {
            anyhow::anyhow!("redact: segment is encrypted but no master key is available")
        })?;
        let (nonce, ct) = super::crypto::split_encrypted(blob)?;
        std::borrow::Cow::Owned(
            super::crypto::decrypt_blob(key, &nonce, &header_bytes, ct).with_context(|| {
                format!("decrypt sealed WAL segment {}", segment_path.display())
            })?,
        )
    } else {
        std::borrow::Cow::Borrowed(blob)
    };
    // Decompress with the zip-bomb cap (a crafted blob can't OOM the daemon).
    let mut frames = decompress_frames(&compressed_blob)
        .with_context(|| format!("decompress sealed WAL segment {}", segment_path.display()))?;

    let staged = redact_frames_in_buffer(
        &mut frames,
        &mut predicate,
        header_len as u64,
        segment_path,
        /* allow_torn_tail = */ false,
    )?;
    refuse_chain_structural_rewrite(segment_path, &staged)?;
    let report = staged.report;

    // No predicate match ⇒ leave the file byte-identical (no needless recompress
    // /rename). Frames skipped or already-redacted both land here.
    if report.frames_redacted.is_empty() {
        return Ok(report);
    }

    let recompressed = compress_frames(&frames)
        .with_context(|| format!("recompress redacted WAL segment {}", segment_path.display()))?;

    // CRYPTO-04f — re-encrypt if the segment was encrypted, with a FRESH nonce
    // (SIV tolerates reuse, but a new nonce is cleaner for auditors). The
    // preserved plaintext header stays the AAD.
    let body: Vec<u8> = if was_encrypted {
        let key = super::master_key::default_segment_key()
            .ok_or_else(|| anyhow::anyhow!("redact: cannot re-encrypt without the master key"))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| anyhow::anyhow!("redact re-encrypt nonce RNG: {e}"))?;
        let ct = super::crypto::encrypt_blob(key, &nonce, &header_bytes, &recompressed)
            .context("re-encrypt redacted segment")?;
        super::crypto::frame_encrypted(&nonce, &ct)
    } else {
        recompressed
    };

    // Atomic rewrite via the shared helper (same contract as the live-segment
    // path): write tmp → fsync → rename over original → parent fsync.
    write_tmp_and_rename(segment_path, &header_bytes, &body)?;
    Ok(report)
}

/// Walk frames in an in-memory decompressed buffer and redact the ones whose
/// payload satisfies `predicate` (zero payload + set `REDACTED` + recompute
/// CRC), mirroring the on-disk [`scan_and_redact`] walk but in logical space.
///
/// `base_offset` is added to each frame's 0-based buffer position when recording
/// it in `frames_redacted`, so the reported offsets live in the same logical-
/// segment coordinate space `neoth verify` uses (`header_len + pos`).
///
/// Same tamper-refusal contract as the disk walk: a bad MAGIC at a full-sized
/// frame slot is corruption (NOT a torn tail) and bails loudly — never a silent
/// skip that would let `memory::forget` report a clean redaction over an
/// unscrubbed segment.
fn redact_frames_in_buffer<F>(
    frames: &mut [u8],
    predicate: &mut F,
    base_offset: u64,
    segment_path: &Path,
    allow_torn_tail: bool,
) -> Result<StagedRedaction>
where
    F: FnMut(&[u8]) -> bool,
{
    let mut staged = StagedRedaction::default();
    let buf_len = frames.len() as u64;
    let mut cursor: u64 = 0;

    while cursor + (PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN) as u64 <= buf_len {
        let start = cursor as usize;
        if frames[start..start + PREAMBLE_LEN] != MAGIC {
            anyhow::bail!(
                "wal::redact: bad frame magic at logical offset {} in decompressed segment {} — \
                 tamper-suspect corruption (not a torn tail); refusing to report a clean \
                 redaction over an unscrubbed segment",
                base_offset + cursor,
                segment_path.display()
            );
        }
        // Copy the header bytes out so no borrow of `frames` survives into the
        // mutation below.
        let mut hdr_arr = [0u8; HEADER_BODY_LEN];
        hdr_arr
            .copy_from_slice(&frames[start + PREAMBLE_LEN..start + PREAMBLE_LEN + HEADER_BODY_LEN]);
        let header = EventHeaderV2::from_le_bytes(&hdr_arr)
            .with_context(|| format!("parse header at logical offset {}", base_offset + cursor))?;
        let total_len = header.total_len as u64;
        let total = total_len as usize;
        // An undersized total_len is always corruption (sealed or live).
        if total < PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN {
            anyhow::bail!(
                "wal::redact: frame at logical offset {} in {} has an undersized \
                 total_len ({total_len}) — corrupt/tampered body; refusing",
                base_offset + cursor,
                segment_path.display()
            );
        }
        // A frame that runs past the buffer boundary:
        //  - Sealed segment: byte-complete by construction → corruption, bail.
        //  - Live segment (`allow_torn_tail`): unclean shutdown may leave a
        //    partial last frame; treat as end of readable frames (break).
        if cursor + total_len > buf_len {
            if allow_torn_tail {
                break;
            }
            anyhow::bail!(
                "wal::redact: frame at logical offset {} in decompressed segment {} has an \
                 out-of-range total_len ({total_len}) — corrupt/tampered sealed body; refusing \
                 to report a clean redaction over an unscrubbed segment",
                base_offset + cursor,
                segment_path.display()
            );
        }

        let payload_start = start + PREAMBLE_LEN + HEADER_BODY_LEN + header.reserved_len as usize;
        let payload_len = header.payload_len as usize;
        // Length-field consistency: reserved + payload + CRC must sit INSIDE the
        // frame. A corrupt `reserved_len`/`payload_len` summing past `total_len`
        // would otherwise index past the frame (into the next one or out of
        // bounds → panic). Refuse it as tamper rather than risk a panic.
        if payload_start + payload_len + CRC_LEN > start + total {
            anyhow::bail!(
                "wal::redact: frame at logical offset {} in decompressed segment {} has \
                 inconsistent reserved_len/payload_len (overruns its total_len) — tamper-suspect; \
                 refusing",
                base_offset + cursor,
                segment_path.display()
            );
        }
        let crc_offset = start + total - CRC_LEN;
        let stored_crc = u32::from_le_bytes(
            frames[crc_offset..crc_offset + CRC_LEN]
                .try_into()
                .expect("validated frame CRC slice has fixed length"),
        );
        let computed_crc = crc32c::crc32c(&frames[start..crc_offset]);
        if stored_crc != computed_crc {
            anyhow::bail!(
                "wal::redact: CRC mismatch at logical offset {} in {} — tamper-suspect \
                 frame; refusing to repair corruption through redaction",
                base_offset + cursor,
                segment_path.display()
            );
        }
        let is_chain_structure = is_authenticated_chain_structure(&header);
        staged.contains_authenticated_chain_structure |= is_chain_structure;
        if header.flags.contains(EventFlags::REDACTED) {
            staged.report.already_redacted += 1;
            cursor += total_len;
            continue;
        }
        let predicate_matched = predicate(&frames[payload_start..payload_start + payload_len]);
        if is_chain_structure {
            staged.matched_authenticated_chain_structure |= predicate_matched;
            if !predicate_matched {
                staged.report.frames_skipped += 1;
            }
            cursor += total_len;
            continue;
        }
        if !predicate_matched {
            staged.report.frames_skipped += 1;
            cursor += total_len;
            continue;
        }
        if is_installed_skill_runtime_proof(&header) {
            anyhow::bail!(
                "wal::redact: topic matched protected installed-Skill runtime proof \
                 {} at logical offset {} in {}; refusing to invalidate live authority",
                super::events::extended_subtype_name(header.event_subtype),
                base_offset + cursor,
                segment_path.display()
            );
        }

        // Redact in the buffer: zero payload, flip REDACTED, recompute CRC over
        // the rewritten frame (mirrors `redact_frame_in_place`).
        for b in &mut frames[payload_start..payload_start + payload_len] {
            *b = 0;
        }
        let new_flags = (header.flags | EventFlags::REDACTED).bits();
        frames[start + PREAMBLE_LEN + FLAGS_OFFSET_IN_HEADER_BODY] = new_flags;
        let new_crc = crc32c::crc32c(&frames[start..start + total - CRC_LEN]);
        frames[start + total - CRC_LEN..start + total].copy_from_slice(&new_crc.to_le_bytes());

        staged.report.frames_redacted.push(base_offset + cursor);
        staged.report.bytes_redacted += payload_len as u64;
        cursor += total_len;
    }

    // A sealed segment's frame stream is byte-complete: a clean walk consumes
    // every byte, ending exactly at `buf_len`. Leftover bytes that cannot form a
    // full frame are trailing garbage / truncation — corruption for a sealed
    // body. Refuse rather than silently treat them as "nothing left to redact"
    // (which would let `memory::forget` report a clean redaction over them).
    // For a live segment (`allow_torn_tail`) the loop already `break`s at a
    // partial frame, so leftover bytes here are the expected torn-tail remnant —
    // not an error.
    if !allow_torn_tail && cursor < buf_len {
        anyhow::bail!(
            "wal::redact: decompressed sealed segment {} has {} undecodable trailing byte(s) at \
             logical offset {} — corrupt/tampered body; refusing to report a clean redaction",
            segment_path.display(),
            buf_len - cursor,
            base_offset + cursor
        );
    }

    Ok(staged)
}

/// Idempotent low-level primitive: take an open r/w file positioned
/// anywhere + a frame offset + the already-parsed header, and rewrite
/// the frame so its payload is zeros, its REDACTED flag is set, and
/// its CRC is recomputed.
///
/// Test-only low-level primitive used by verifier/redaction regression tests.
/// Production topic scans always use the path-bound sidecar lock and
/// crash-consistent atomic replacement path above; exposing an unlocked
/// `File`-only rewrite API would let a future caller bypass that contract.
///
/// Installed-Skill mutation/authority proof frames and authenticated
/// chain-structural frames are rejected before the first write. Their payloads
/// are live execution/verification inputs rather than operator memory content.
/// The header is re-read from `file` at `frame_offset` and must exactly match
/// the supplied parsed header, so a stale or forged caller argument cannot
/// bypass that classification.
#[cfg(test)]
pub(crate) fn redact_frame_in_place(
    file: &mut std::fs::File,
    frame_offset: u64,
    header: &EventHeaderV2,
) -> Result<()> {
    file.seek(SeekFrom::Start(frame_offset))
        .context("seek to frame start for redaction header verification")?;
    let mut preamble = [0u8; PREAMBLE_LEN];
    file.read_exact(&mut preamble)
        .context("read frame magic for redaction header verification")?;
    anyhow::ensure!(
        preamble == MAGIC,
        "refusing direct redaction at offset {frame_offset}: actual frame magic is invalid"
    );
    let mut actual_header_bytes = [0u8; HEADER_BODY_LEN];
    file.read_exact(&mut actual_header_bytes)
        .context("read actual frame header for redaction verification")?;
    let actual_header = EventHeaderV2::from_le_bytes(&actual_header_bytes)
        .context("parse actual frame header for redaction verification")?;
    anyhow::ensure!(
        actual_header == *header,
        "refusing direct redaction at offset {frame_offset}: supplied header does not match \
         the actual on-disk frame header"
    );
    let total_len = actual_header.total_len as usize;
    anyhow::ensure!(
        actual_header.payload_len as usize <= crate::wal::writer::MAX_PAYLOAD_BYTES,
        "refusing direct redaction at offset {frame_offset}: actual payload length {} \
         exceeds the WAL payload ceiling {}",
        actual_header.payload_len,
        crate::wal::writer::MAX_PAYLOAD_BYTES
    );
    anyhow::ensure!(
        total_len <= crate::wal::recovery::MAX_FRAME_LEN,
        "refusing direct redaction at offset {frame_offset}: actual frame length {total_len} \
         exceeds the WAL frame ceiling {}",
        crate::wal::recovery::MAX_FRAME_LEN
    );
    let frame_end = frame_offset
        .checked_add(u64::try_from(total_len).context("actual frame length exceeds u64")?)
        .context("actual frame end offset overflow")?;
    let file_len = file
        .metadata()
        .context("stat actual frame before direct redaction")?
        .len();
    anyhow::ensure!(
        frame_end <= file_len,
        "refusing direct redaction at offset {frame_offset}: actual frame ends at {frame_end}, \
         beyond the {file_len}-byte file"
    );
    let mut actual_frame = vec![0u8; total_len];
    file.seek(SeekFrom::Start(frame_offset))
        .context("seek to actual frame for redaction integrity verification")?;
    file.read_exact(&mut actual_frame)
        .context("read actual frame for redaction integrity verification")?;
    let decoded = super::frame::decode_frame(&actual_frame)
        .context("verify actual frame CRC before direct redaction")?;
    anyhow::ensure!(
        decoded.header == actual_header,
        "refusing direct redaction at offset {frame_offset}: decoded frame identity changed \
         during verification"
    );
    anyhow::ensure!(
        !is_installed_skill_runtime_proof(&actual_header),
        "refusing to redact protected installed-Skill runtime proof {}",
        super::events::extended_subtype_name(actual_header.event_subtype)
    );
    anyhow::ensure!(
        !is_authenticated_chain_structure(&actual_header),
        "refusing direct physical redaction of authenticated chain-structural frame at offset \
         {frame_offset}; physical redaction awaits an authenticated rewrite transaction; logical \
         forget is still usable"
    );
    let payload_offset = frame_offset
        + (PREAMBLE_LEN + HEADER_BODY_LEN + actual_header.reserved_len as usize) as u64;
    let payload_len = actual_header.payload_len as usize;

    // 1. Zero the payload.
    let zeros = vec![0u8; payload_len];
    file.seek(SeekFrom::Start(payload_offset))
        .context("seek to payload for zero-fill")?;
    file.write_all(&zeros)
        .context("write zero-fill over payload")?;

    // 2. Flip the REDACTED flag in the header. Flags live at
    // FLAGS_OFFSET_IN_HEADER_BODY of the header body; absolute offset =
    // frame_offset + PREAMBLE_LEN + FLAGS_OFFSET_IN_HEADER_BODY.
    let new_flags = (actual_header.flags | EventFlags::REDACTED).bits();
    file.seek(SeekFrom::Start(
        frame_offset + PREAMBLE_LEN as u64 + FLAGS_OFFSET_IN_HEADER_BODY as u64,
    ))
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
    file.flush()
        .context("flush completed payload/flag/CRC frame rewrite")?;

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
    let signed_msg = redaction_authorisation_message(
        &segment_name,
        redacted_offsets,
        bytes_redacted,
        topic,
        now_unix,
    );
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

    #[cfg(unix)]
    #[test]
    fn rewrite_lock_rejects_a_symlink_leaf_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        let outside = dir.path().join("outside.lock");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, segment_rewrite_lock_path(&segment)).unwrap();

        let error = lock_segment_for_rewrite(&segment)
            .err()
            .expect("rewrite lock symlink must fail closed");
        assert!(
            format!("{error:#}").contains("without following links")
                || format!("{error:#}").contains("real regular file"),
            "unexpected no-follow refusal: {error:#}"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    /// Build a frame header for testing (matches the `populated_header`
    /// pattern in `wal::frame::tests` but private to this module to
    /// avoid cross-test coupling).
    fn make_header(payload_len: u32, event_id: u64) -> EventHeaderV2 {
        make_typed_header(payload_len, event_id, 0x01, 0)
    }

    fn make_typed_header(
        payload_len: u32,
        event_id: u64,
        event_type: u8,
        event_subtype: u8,
    ) -> EventHeaderV2 {
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type,
            event_subtype,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len as usize + CRC_LEN) as u32,
            payload_len,
            generation: 1,
            event_id: EventId(event_id),
            hlc: Hlc::new(1_700_000_000_000_000_000, event_id as u32).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: crate::wal::types::WalScope::UNSET,
            category: crate::wal::types::WalCategory::UNSET,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: 0xdeadbeef,
        }
    }

    /// Write a fresh segment file containing N frames with operator-
    /// supplied payloads. Returns `(TempDir, path, offsets)` — caller must
    /// keep `_dir` alive; uses a TempDir (not NamedTempFile) so the atomic
    /// rename-over in the new crash-consistent path works on Windows (no
    /// competing open handle).
    fn write_segment_with_frames(
        payloads: &[&[u8]],
    ) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
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
        std::fs::write(&path, &bytes).unwrap();
        (dir, path, offsets)
    }

    /// Write a *live* v2 segment file: 61-byte v2 header (COMPRESSED flag set)
    /// followed by RAW frames — exactly what the writer produces before clean
    /// finalize. Returns `(TempDir, path, offsets)` — caller keeps `_dir` alive.
    fn write_v2_live_segment_with_frames(
        payloads: &[&[u8]],
    ) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
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
        std::fs::write(&path, &bytes).unwrap();
        (dir, path, offsets)
    }

    fn write_segment_with_typed_frame(
        event_type: u8,
        event_subtype: u8,
        payload: &[u8],
    ) -> (tempfile::TempDir, std::path::PathBuf, u64, EventHeaderV2) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let mut bytes = SegmentHeader::new(1, 1, 0, 0, [0u8; 16])
            .to_le_bytes()
            .to_vec();
        let offset = bytes.len() as u64;
        let header = make_typed_header(payload.len() as u32, 1, event_type, event_subtype);
        bytes.extend_from_slice(&encode_frame(&header, payload));
        std::fs::write(&path, bytes).unwrap();
        (dir, path, offset, header)
    }

    fn encode_typed_frame_stream(frames: &[(u8, &[u8])], base_offset: u64) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = Vec::new();
        let mut offsets = Vec::with_capacity(frames.len());
        for (index, (event_type, payload)) in frames.iter().enumerate() {
            offsets.push(base_offset + bytes.len() as u64);
            let header =
                make_typed_header(payload.len() as u32, (index + 1) as u64, *event_type, 0);
            bytes.extend_from_slice(&encode_frame(&header, payload));
        }
        (bytes, offsets)
    }

    fn write_segment_with_typed_frames(
        frames: &[(u8, &[u8])],
    ) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let header = SegmentHeader::new(1, 1, 0, 0, [0u8; 16]).to_le_bytes();
        let (body, offsets) = encode_typed_frame_stream(frames, header.len() as u64);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&body);
        std::fs::write(&path, bytes).unwrap();
        (dir, path, offsets)
    }

    fn assert_authenticated_rewrite_refusal(error: &anyhow::Error) {
        let message = format!("{error:#}");
        assert!(
            message.contains("authenticated rewrite transaction"),
            "refusal must name the required authenticated rewrite transaction: {message}"
        );
        assert!(
            message.contains("logical forget is still usable"),
            "refusal must preserve the logical-forget recovery path: {message}"
        );
    }

    #[test]
    fn physical_topic_redaction_refuses_every_installed_skill_runtime_proof() {
        let proof_subtypes = [
            crate::wal::events::ExtendedSubtype::SkillInstallIntent,
            crate::wal::events::ExtendedSubtype::SkillInstallResult,
            crate::wal::events::ExtendedSubtype::SkillRemovalIntent,
            crate::wal::events::ExtendedSubtype::SkillRemovalResult,
            crate::wal::events::ExtendedSubtype::SkillAuthorityDecision,
        ];

        for subtype in proof_subtypes {
            let (_dir, path, _, _) = write_segment_with_typed_frame(
                crate::wal::events::EVENT_TYPE_EXTENDED,
                subtype as u8,
                br#"{"skill_id":"alpha","topic":"operator-request"}"#,
            );
            let before = std::fs::read(&path).unwrap();

            let error = scan_and_redact(&path, payload_contains_topic("alpha"))
                .expect_err("runtime proof payload must be non-redactable");

            assert!(
                format!("{error:#}").contains("protected installed-Skill runtime proof"),
                "{subtype:?} returned unexpected refusal: {error:#}"
            );
            assert!(
                format!("{error:#}").contains(subtype.name()),
                "refusal must identify {subtype:?}: {error:#}"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                before,
                "{subtype:?} bytes changed despite the categorical refusal"
            );
        }
    }

    #[test]
    fn protected_proof_refusal_does_not_commit_earlier_staged_redactions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let mut bytes = SegmentHeader::new(1, 1, 0, 0, [0u8; 16])
            .to_le_bytes()
            .to_vec();
        for (event_id, subtype, payload) in [
            (
                1,
                crate::wal::events::ExtendedSubtype::CommunicationProfileUpdated,
                br#"{"topic":"alpha","kind":"ordinary-memory"}"#.as_slice(),
            ),
            (
                2,
                crate::wal::events::ExtendedSubtype::SkillAuthorityDecision,
                br#"{"skill_id":"alpha","kind":"runtime-proof"}"#.as_slice(),
            ),
        ] {
            let header = make_typed_header(
                payload.len() as u32,
                event_id,
                crate::wal::events::EVENT_TYPE_EXTENDED,
                subtype as u8,
            );
            bytes.extend_from_slice(&encode_frame(&header, payload));
        }
        std::fs::write(&path, &bytes).unwrap();

        let error = scan_and_redact(&path, payload_contains_topic("alpha"))
            .expect_err("a later protected match must abort the segment transaction");

        assert!(format!("{error:#}").contains("skill_authority_decision"));
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "an earlier ordinary match was only staged and must not reach disk"
        );
    }

    #[test]
    fn topic_redaction_cannot_repair_a_tampered_proof_subtype_into_unprotected_data() {
        let (_dir, path, offset, _) = write_segment_with_typed_frame(
            crate::wal::events::EVENT_TYPE_EXTENDED,
            crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8,
            br#"{"skill_id":"alpha"}"#,
        );
        let mut tampered = std::fs::read(&path).unwrap();
        tampered[offset as usize + PREAMBLE_LEN + 3] =
            crate::wal::events::ExtendedSubtype::CommunicationProfileUpdated as u8;
        std::fs::write(&path, &tampered).unwrap();

        let error = scan_and_redact(&path, payload_contains_topic("alpha"))
            .expect_err("redaction must not turn a CRC-invalid subtype rewrite into valid data");

        assert!(format!("{error:#}").contains("CRC mismatch"), "{error:#}");
        assert_eq!(
            std::fs::read(path).unwrap(),
            tampered,
            "tamper refusal must not repair or otherwise rewrite the segment"
        );
    }

    #[test]
    fn direct_frame_redaction_refuses_installed_skill_runtime_proof() {
        let (_dir, path, offset, header) = write_segment_with_typed_frame(
            crate::wal::events::EVENT_TYPE_EXTENDED,
            crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8,
            br#"{"skill_id":"alpha"}"#,
        );
        let before = std::fs::read(&path).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let error = redact_frame_in_place(&mut file, offset, &header)
            .expect_err("direct offset redaction must share the proof policy");

        assert!(format!("{error:#}").contains("protected installed-Skill runtime proof"));
        drop(file);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn direct_frame_redaction_cannot_spoof_any_proof_with_an_unprotected_header() {
        for proof_subtype in [
            crate::wal::events::ExtendedSubtype::SkillInstallIntent,
            crate::wal::events::ExtendedSubtype::SkillInstallResult,
            crate::wal::events::ExtendedSubtype::SkillRemovalIntent,
            crate::wal::events::ExtendedSubtype::SkillRemovalResult,
            crate::wal::events::ExtendedSubtype::SkillAuthorityDecision,
        ] {
            let (_dir, path, offset, actual_header) = write_segment_with_typed_frame(
                crate::wal::events::EVENT_TYPE_EXTENDED,
                proof_subtype as u8,
                br#"{"skill_id":"alpha"}"#,
            );
            let before = std::fs::read(&path).unwrap();
            let mut forged_header = actual_header;
            forged_header.event_subtype =
                crate::wal::events::ExtendedSubtype::CommunicationProfileUpdated as u8;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();

            let error = redact_frame_in_place(&mut file, offset, &forged_header).expect_err(
                "caller-supplied frame identity cannot override on-disk proof identity",
            );

            assert!(
                format!("{error:#}").contains("supplied header does not match"),
                "{proof_subtype:?}: {error:#}"
            );
            drop(file);
            assert_eq!(
                std::fs::read(path).unwrap(),
                before,
                "{proof_subtype:?}: mismatched caller metadata must fail before the first write"
            );
        }
    }

    #[test]
    fn direct_frame_redaction_rejects_oversized_header_before_allocation_or_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-frame.wal");
        let header = make_typed_header(
            (crate::wal::writer::MAX_PAYLOAD_BYTES + 1) as u32,
            1,
            0x01,
            0,
        );
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&header.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let error = redact_frame_in_place(&mut file, 0, &header)
            .expect_err("oversized caller header must be bounded before allocation");

        assert!(
            format!("{error:#}").contains("payload ceiling"),
            "{error:#}"
        );
        drop(file);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn direct_frame_redaction_rejects_truncated_frame_before_allocation_or_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated-frame.wal");
        let header = make_typed_header(128, 1, 0x01, 0);
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&header.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let error = redact_frame_in_place(&mut file, 0, &header)
            .expect_err("truncated frame must fail the metadata bound before allocation");

        assert!(format!("{error:#}").contains("beyond the"), "{error:#}");
        drop(file);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn unprotected_extended_frame_remains_topic_redactable() {
        let (_dir, path, offset, _) = write_segment_with_typed_frame(
            crate::wal::events::EVENT_TYPE_EXTENDED,
            crate::wal::events::ExtendedSubtype::CommunicationProfileUpdated as u8,
            br#"{"topic":"alpha"}"#,
        );

        let report =
            scan_and_redact(&path, payload_contains_topic("alpha")).expect("redact normal event");

        assert_eq!(report.frames_redacted, vec![offset]);
    }

    #[test]
    fn scan_redacts_matching_frames_in_a_v2_live_segment() {
        // GOLD-ARCH-03 regression: a live v2 segment has a 61-byte header. The
        // pre-fix hardcoded SEGMENT_HEADER_LEN (60) start offset failed the
        // MAGIC check on frame 1 and SILENTLY redacted nothing — a privacy
        // hole. With the header-length fix the matching frame is scrubbed.
        let (_dir, path, offsets) =
            write_v2_live_segment_with_frames(&[b"hello world", b"AcmeCorp is a secret"]);
        let report = scan_and_redact(&path, payload_contains_topic("acmecorp")).expect("redact");
        assert_eq!(report.frames_redacted_count(), 1, "v2 frame must be found");
        assert_eq!(report.frames_redacted, vec![offsets[1]]);
        assert_eq!(report.frames_skipped, 1);
    }

    #[test]
    fn raw_chain_structural_segment_refuses_matching_physical_redaction_byte_identically() {
        for structural_type in [
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER,
            crate::wal::events::EVENT_TYPE_REDACTION_MARKER,
        ] {
            let frames: &[(u8, &[u8])] = &[
                (0x01, b"AcmeCorp user memory"),
                (structural_type, b"AcmeCorp authenticated chain structure"),
            ];
            let (_dir, path, _) = write_segment_with_typed_frames(frames);
            let before = std::fs::read(&path).expect("read raw segment before refusal");

            let error = scan_and_redact(&path, payload_contains_topic("acmecorp"))
                .expect_err("chain-structural segment must await authenticated rewrite");

            assert_authenticated_rewrite_refusal(&error);
            assert_eq!(
                std::fs::read(&path).expect("read raw segment after refusal"),
                before,
                "raw chain-structural refusal must not publish staged frame edits"
            );
        }
    }

    /// Write a *sealed compressed* (v2/zstd) segment: 61-byte v2 header with the
    /// COMPRESSED flag set, followed by `compress_frames(raw_frames)` — exactly
    /// what the writer's `finalize_compressed_segment` produces. Returns the
    /// TempDir (keep it alive — drop removes the dir), the segment path, and the
    /// LOGICAL offset (`header_len + pos`) of each frame. A real on-disk path in
    /// a tempdir (NOT a NamedTempFile) so the atomic rename-over has no rival
    /// open handle on Windows.
    fn write_sealed_compressed_segment(
        payloads: &[&[u8]],
    ) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let mut raw = Vec::new();
        let mut offsets = Vec::with_capacity(payloads.len());
        for (i, p) in payloads.iter().enumerate() {
            offsets.push(SEGMENT_HEADER_V2_LEN as u64 + raw.len() as u64);
            let h = make_header(p.len() as u32, (i + 1) as u64);
            raw.extend_from_slice(&encode_frame(&h, p));
        }
        let blob = compress_frames(&raw).expect("compress");
        let mut bytes = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&blob);
        std::fs::write(&path, &bytes).unwrap();
        (dir, path, offsets)
    }

    /// Decompress a sealed segment's body back to raw frame bytes for assertions.
    fn decompress_segment_frames(path: &std::path::Path) -> Vec<u8> {
        use crate::wal::compress::decompress_frames;
        use crate::wal::segment_header::SEGMENT_HEADER_V2_LEN;
        let bytes = std::fs::read(path).unwrap();
        decompress_frames(&bytes[SEGMENT_HEADER_V2_LEN..]).expect("decompress sealed body")
    }

    #[test]
    fn scan_redacts_a_matching_frame_in_a_sealed_compressed_segment() {
        // GOLD-ARCH-03b: a finalised zstd segment is now redacted via decompress
        // → redact-in-logical-space → recompress → atomic rewrite (was: refuse).
        // The matching frame is scrubbed; the file re-seals + re-decompresses.
        let (_dir, path, offsets) =
            write_sealed_compressed_segment(&[b"keep this frame", b"AcmeCorp is a secret"]);
        let report = scan_and_redact(&path, payload_contains_topic("acmecorp"))
            .expect("redact sealed segment");
        assert_eq!(
            report.frames_redacted_count(),
            1,
            "sealed frame must be found"
        );
        assert_eq!(report.frames_skipped, 1);
        // Offsets recorded in LOGICAL space (header_len + pos) so a 0xF3 marker
        // aligns with what `neoth verify` computes over the reconstructed segment.
        assert_eq!(report.frames_redacted, vec![offsets[1]]);

        // Still a valid compressed v2 segment + re-decompresses clean.
        let raw = std::fs::read(&path).unwrap();
        let parsed = parse_segment_header(&raw).expect("still a parseable segment header");
        assert!(parsed.is_compressed(), "segment must remain compressed v2");
        let frames = decompress_segment_frames(&path);
        let f0 = decode_frame(&frames).expect("frame 0 decodes");
        assert!(
            !f0.header.flags.contains(EventFlags::REDACTED),
            "non-matching frame untouched"
        );
        let f1 = decode_frame(&frames[f0.header.total_len as usize..]).expect("frame 1 decodes");
        assert!(
            f1.header.flags.contains(EventFlags::REDACTED),
            "matching frame carries REDACTED"
        );
        assert!(f1.payload.iter().all(|b| *b == 0), "matched payload zeroed");
        // Chain-of-evidence anchors preserved.
        assert_eq!(f1.header.event_id.0, 2);
        assert_eq!(f1.header.payload_hash, 0xdeadbeef);
    }

    #[test]
    fn sealed_compressed_redaction_is_idempotent() {
        let (_dir, path, _) = write_sealed_compressed_segment(&[b"AcmeCorp row"]);
        let first = scan_and_redact(&path, payload_contains_topic("acme")).unwrap();
        assert_eq!(first.frames_redacted_count(), 1);
        // Second pass: the frame now carries REDACTED inside the re-sealed blob →
        // skipped, no rewrite.
        let second = scan_and_redact(&path, payload_contains_topic("acme")).unwrap();
        assert_eq!(second.frames_redacted_count(), 0);
        assert_eq!(second.already_redacted, 1);
    }

    #[test]
    fn sealed_compressed_no_match_leaves_file_byte_identical() {
        let (_dir, path, _) = write_sealed_compressed_segment(&[b"alpha", b"beta"]);
        let before = std::fs::read(&path).unwrap();
        let report = scan_and_redact(&path, payload_contains_topic("nope")).unwrap();
        assert_eq!(report.frames_redacted_count(), 0);
        assert_eq!(report.frames_skipped, 2);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "a no-match sealed segment must not be recompressed/rewritten"
        );
    }

    #[test]
    fn sealed_chain_structural_segment_refuses_matching_physical_redaction_byte_identically() {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let frames: &[(u8, &[u8])] = &[
            (0x01, b"AcmeCorp user memory"),
            (
                crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
                b"authenticated chain structure",
            ),
        ];
        let (raw_frames, _) = encode_typed_frame_stream(frames, SEGMENT_HEADER_V2_LEN as u64);
        let mut bytes = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&compress_frames(&raw_frames).expect("compress typed frames"));
        std::fs::write(&path, bytes).expect("write sealed chain-structural segment");
        let before = std::fs::read(&path).expect("read sealed segment before refusal");

        let error = scan_and_redact(&path, payload_contains_topic("acmecorp"))
            .expect_err("sealed chain-structural segment must await authenticated rewrite");

        assert_authenticated_rewrite_refusal(&error);
        assert_eq!(
            std::fs::read(&path).expect("read sealed segment after refusal"),
            before,
            "sealed chain-structural refusal must not recompress or publish staged frame edits"
        );
    }

    #[test]
    fn sealed_compressed_refuses_corrupt_frame_magic_in_body() {
        // The tamper-refusal contract holds in logical space: a corrupt frame
        // MAGIC inside the decompressed body bails loudly rather than silently
        // skipping the rest (a false "clean redaction" over unscrubbed data).
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let mut raw = Vec::new();
        let h0 = make_header(b"first frame ok".len() as u32, 1);
        raw.extend_from_slice(&encode_frame(&h0, b"first frame ok"));
        let frame1_off = raw.len();
        let h1 = make_header(b"AcmeCorp secret".len() as u32, 2);
        raw.extend_from_slice(&encode_frame(&h1, b"AcmeCorp secret"));
        for b in raw[frame1_off..frame1_off + PREAMBLE_LEN].iter_mut() {
            *b ^= 0xFF;
        }
        let blob = compress_frames(&raw).expect("compress");
        let mut bytes = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&blob);
        std::fs::write(&path, &bytes).unwrap();
        let err = scan_and_redact(&path, payload_contains_topic("acmecorp"))
            .expect_err("must refuse a corrupt frame magic in the decompressed body");
        assert!(
            err.to_string().contains("bad frame magic"),
            "error should name the bad-magic refusal: {err}"
        );
    }

    #[test]
    fn sealed_compressed_refuses_a_truncated_frame_in_body() {
        // A sealed body is byte-complete by construction; a frame whose total_len
        // runs past the decompressed buffer is corruption/tamper → must BAIL, not
        // silently partial-walk and report a clean redaction (GOLD-ARCH-03b
        // adversarial-review HIGH: the truncated-tail privacy hole).
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.wal");
        let mut raw = Vec::new();
        let h0 = make_header(b"first frame ok".len() as u32, 1);
        raw.extend_from_slice(&encode_frame(&h0, b"first frame ok"));
        // Second frame with a 50-byte payload carrying the topic.
        let big_payload = b"AcmeCorp secret payload long enough to truncate xx"; // 50 bytes
        let h1 = make_header(big_payload.len() as u32, 2);
        raw.extend_from_slice(&encode_frame(&h1, big_payload));
        // Lop 30 bytes off the tail: frame 2's header still claims its full
        // total_len, but its payload+CRC now run past the shortened buffer.
        raw.truncate(raw.len() - 30);
        let blob = compress_frames(&raw).expect("compress");
        let mut bytes = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&blob);
        std::fs::write(&path, &bytes).unwrap();
        let err = scan_and_redact(&path, payload_contains_topic("acmecorp"))
            .expect_err("must refuse a truncated frame in the decompressed body");
        assert!(
            err.to_string().contains("total_len"),
            "error should name the out-of-range total_len: {err}"
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
    fn scan_refuses_a_corrupt_mid_segment_frame_magic_h2() {
        // H2 (2026-06-12): a full-sized frame slot whose MAGIC is corrupted
        // mid-segment is tamper/corruption, not a torn tail. The old `break`
        // returned Ok(errors=0) → `forget --physical` reported a confirmed
        // GDPR erasure while frames from the corrupt one on were left
        // UN-redacted (a false privacy guarantee). Must now REFUSE (Err) so
        // GR-008 fires. FAILS pre-fix (Ok, frame 2 silently skipped).
        let (_dir, path, offsets) =
            write_segment_with_frames(&[b"first frame is fine", b"AcmeCorp is a secret to scrub"]);
        // Corrupt the 4-byte MAGIC preamble of the SECOND frame.
        let mut bytes = std::fs::read(&path).unwrap();
        let off = offsets[1] as usize;
        for b in bytes[off..off + PREAMBLE_LEN].iter_mut() {
            *b ^= 0xFF;
        }
        std::fs::write(&path, &bytes).unwrap();
        let err = scan_and_redact(&path, payload_contains_topic("acmecorp"))
            .expect_err("must refuse a corrupt mid-segment frame magic");
        assert!(
            err.to_string().contains("bad frame magic"),
            "error should name the bad-magic refusal: {err}"
        );
    }

    #[test]
    fn scan_redacts_only_matching_frames_and_skips_others() {
        let (_dir, path, offsets) = write_segment_with_frames(&[
            b"hello world",
            b"AcmeCorp is a secret",
            b"another unrelated frame",
            b"more AcmeCorp data here",
        ]);
        let predicate = payload_contains_topic("acmecorp");
        let report = scan_and_redact(&path, predicate).expect("redact");
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
        let (_dir, path, _) = write_segment_with_frames(&[b"AcmeCorp owns this row"]);
        let predicate = payload_contains_topic("acme");
        scan_and_redact(&path, predicate).expect("redact");

        // Walk the segment + decode the single frame; payload must
        // now be zeros + flag must carry REDACTED.
        let bytes = std::fs::read(&path).unwrap();
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
        let (_dir, path, _) = write_segment_with_frames(&[b"AcmeCorp row"]);
        let pred = payload_contains_topic("acme");
        let first = scan_and_redact(&path, pred).unwrap();
        assert_eq!(first.frames_redacted_count(), 1);
        // Second pass: the same predicate would match again on a
        // fresh frame, but the REDACTED flag now blocks the scan
        // from touching it twice.
        let pred2 = payload_contains_topic("acme");
        let second = scan_and_redact(&path, pred2).unwrap();
        assert_eq!(second.frames_redacted_count(), 0);
        assert_eq!(second.already_redacted, 1);
    }

    #[test]
    fn scan_returns_empty_report_on_segment_with_no_matches() {
        let (_dir, path, _) = write_segment_with_frames(&[b"alpha", b"beta", b"gamma"]);
        let pred = payload_contains_topic("nothing-matches-this");
        let report = scan_and_redact(&path, pred).unwrap();
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

    // ── Crash-consistency tests (BUG-W2-P2-WAL-REDACT-CRASH-RECOVERY) ───────

    #[test]
    fn live_segment_durable_rewrite_leaves_no_tmp_and_is_fully_redacted() {
        // After a successful live-segment redaction the `.redact.tmp` must be
        // gone (renamed away on success, or removed on error) and every matched
        // frame must be fully zeroed with the REDACTED flag set.  The old in-
        // place per-frame path had no such atomicity guarantee — a crash between
        // the payload-zero and the CRC rewrite left an inconsistent frame with
        // no recovery record.
        let (_dir, path, offsets) = write_segment_with_frames(&[
            b"keep this one",
            b"AcmeCorp private data",
            b"keep this too",
        ]);
        let dir_path = path.parent().unwrap().to_owned();
        let report = scan_and_redact(&path, payload_contains_topic("acmecorp")).expect("redact");
        assert_eq!(report.frames_redacted_count(), 1);
        assert_eq!(report.frames_redacted, vec![offsets[1]]);

        // No .redact.tmp files must remain — either renamed away on success or
        // cleaned up on any error path.
        let leftover_tmps: Vec<_> = std::fs::read_dir(&dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".redact.tmp"))
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "no .redact.tmp must survive a successful redaction, found: {:?}",
            leftover_tmps.iter().map(|e| e.path()).collect::<Vec<_>>()
        );

        // Matched frame is fully redacted: zeroed payload + REDACTED flag.
        let bytes = std::fs::read(&path).unwrap();
        let decoded_match =
            decode_frame(&bytes[offsets[1] as usize..]).expect("decode matched frame");
        assert!(decoded_match.header.flags.contains(EventFlags::REDACTED));
        assert!(
            decoded_match.payload.iter().all(|b| *b == 0),
            "matched payload must be zeroed"
        );
        // Non-matched frames are untouched.
        let decoded0 = decode_frame(&bytes[offsets[0] as usize..]).expect("decode frame 0");
        assert!(!decoded0.header.flags.contains(EventFlags::REDACTED));
        assert!(
            !decoded0.payload.iter().all(|b| *b == 0),
            "non-matched frame must retain original payload"
        );
    }

    #[test]
    fn live_segment_no_match_leaves_file_byte_identical() {
        // A no-match redaction of a live segment must not rewrite the file at
        // all — the bytes on disk must be identical before and after the call.
        let (_dir, path, _) = write_segment_with_frames(&[b"alpha", b"beta", b"gamma"]);
        let before = std::fs::read(&path).unwrap();
        let report = scan_and_redact(&path, payload_contains_topic("nope")).unwrap();
        assert_eq!(report.frames_redacted_count(), 0);
        assert_eq!(report.frames_skipped, 3);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "no-match live segment must not be rewritten");
    }

    #[test]
    fn concurrent_redactors_serialize_without_resurrecting_prior_scrubs() {
        // P1 regression: before the sidecar exclusion, two redactors could both
        // snapshot the original segment, scrub disjoint frames, then publish in
        // opposite order. The last rename resurrected the first scrub. Hold the
        // first redactor inside its predicate so the second definitely attempts
        // the same segment while the first transaction is still open.
        let (_dir, path, offsets) =
            write_segment_with_frames(&[b"Alpha private row", b"Beta private row"]);

        let (first_entered_tx, first_entered_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let first_path = path.clone();
        let first = std::thread::spawn(move || {
            let mut entered = Some(first_entered_tx);
            let mut release = Some(release_first_rx);
            scan_and_redact(&first_path, move |payload| {
                if let Some(tx) = entered.take() {
                    tx.send(()).expect("announce first redactor snapshot");
                    release
                        .take()
                        .expect("one release receiver")
                        .recv()
                        .expect("release first redactor");
                }
                payload
                    .windows(b"Alpha".len())
                    .any(|window| window == b"Alpha")
            })
        });
        first_entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first redactor reached its snapshot predicate");

        let (second_probe_tx, second_probe_rx) = std::sync::mpsc::channel();
        let second_start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let second_start_thread = second_start.clone();
        let second_path = path.clone();
        let second = std::thread::spawn(move || {
            // Observe the real OS lock directly while the first redactor is
            // blocked inside its predicate. This is deterministic; unlike a
            // sleep/timeout assertion it cannot pass merely because this
            // thread was descheduled before entering `scan_and_redact`.
            let competing = crate::util::locked_file::try_lock_file_once(
                &segment_rewrite_lock_path(&second_path),
                "concurrent redactor exclusion regression",
            )
            .expect("probe first redactor lock");
            second_probe_tx
                .send(competing.is_none())
                .expect("report first redactor lock ownership");
            drop(competing);
            second_start_thread.wait();
            scan_and_redact(&second_path, move |payload| {
                payload
                    .windows(b"Beta".len())
                    .any(|window| window == b"Beta")
            })
        });
        let first_owned_lock = second_probe_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("second redactor observed the live lock");
        // Put the second public redaction call at the lock boundary before
        // releasing the first transaction. The final frame assertions prove
        // that whichever thread the scheduler runs first, no stale snapshot
        // can resurrect the other redactor's payload.
        second_start.wait();
        release_first_tx
            .send(())
            .expect("release first redactor after exclusion probe");

        first
            .join()
            .expect("first redactor thread")
            .expect("first redaction succeeds");
        second
            .join()
            .expect("second redactor thread")
            .expect("second redaction succeeds");
        assert!(
            first_owned_lock,
            "the first redactor must own the stable sidecar before publication"
        );

        let bytes = std::fs::read(&path).expect("read twice-redacted segment");
        for offset in offsets {
            let frame = decode_frame(&bytes[offset as usize..]).expect("decode redacted frame");
            assert!(
                frame.header.flags.contains(EventFlags::REDACTED),
                "both disjoint scrubs must survive the second atomic replacement"
            );
            assert!(frame.payload.iter().all(|byte| *byte == 0));
        }
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
        let (_dir, path, offsets) = write_segment_with_frames(&[
            b"frame-A keep",
            b"frame-B AcmeCorp redact me",
            b"frame-C keep",
        ]);
        let pred = payload_contains_topic("acme");
        scan_and_redact(&path, pred).unwrap();

        let bytes = std::fs::read(&path).unwrap();
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
        assert!(
            payload["signer_pubkey"].as_str().is_some(),
            "marker carries operator pubkey"
        );
        assert!(payload["sig"].as_str().is_some(), "marker is signed");
    }
}
