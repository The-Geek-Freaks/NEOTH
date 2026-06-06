//! HMAC compaction — Phase 33b SP-2.
//!
//! Periodically the WAL writer emits a `0x15 COMPACTION_MARKER` event
//! carrying an HMAC-SHA256 over every frame written since the previous
//! marker. A downstream reader (or `neoth verify`) recomputes the HMAC
//! from the bytes-on-disk and compares — a tampered tail fails.
//!
//! ## Why HMAC, not plain hash
//!
//! A plain hash is forgeable: an attacker who edits the WAL can also
//! rewrite the trailing marker. HMAC requires a key the attacker
//! doesn't have; the key lives in `~/.neoth/wal/hmac.key` with mode 0600.
//! Compromised filesystem access defeats this — but at that point the
//! adversary already has the operator's secrets. The marker is honest
//! tamper-evidence, not crypto-grade evidence.
//!
//! ## Key lifecycle
//!
//! [`load_or_init_key`] reads `~/.neoth/wal/hmac.key` or generates a fresh
//! 32-byte key on first boot and writes it mode 0600 (Windows: icacls
//! grant-r-owner via the same path as WAL segments — see
//! `wal::win_acl::restrict_to_owner`).
//!
//! ## Cadence
//!
//! [`CompactionState`] tracks bytes-since-marker + frames-since-marker.
//! [`should_emit`] returns true when either threshold is exceeded. The
//! writer calls this after each frame and emits a marker when due.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::compress::decompress_frames;
use super::segment_header::parse_segment_header;

type HmacSha256 = Hmac<Sha256>;

/// Default key path: `~/.neoth/wal/hmac.key`.
pub fn default_key_path() -> PathBuf {
    crate::config::FreedomConfig::default_wal_dir().join("hmac.key")
}

/// Emit a marker every 1024 frames OR every 16 MiB. Either threshold
/// gives operators marker coverage within a few minutes of typical use
/// without overwhelming the WAL with metadata events.
pub const MAX_FRAMES_BETWEEN_MARKERS: u32 = 1024;
pub const MAX_BYTES_BETWEEN_MARKERS: u64 = 16 * 1024 * 1024;

/// Running tracker. Writer holds one of these and accumulates frame
/// bytes into the HMAC engine. When [`should_emit`] returns true, the
/// writer calls [`finalise_marker`] to extract the tag + reset.
pub struct CompactionState {
    mac: HmacSha256,
    bytes_since_marker: u64,
    frames_since_marker: u32,
    /// File offset where the current marker window started. Reused as
    /// `from_offset` in the marker payload.
    from_offset: u64,
}

impl CompactionState {
    /// Build a fresh state. `start_offset` is the file offset at which
    /// the first frame in this window will land (usually right after
    /// the segment header on a new segment).
    pub fn new(key: &[u8], start_offset: u64) -> Self {
        let mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        Self {
            mac,
            bytes_since_marker: 0,
            frames_since_marker: 0,
            from_offset: start_offset,
        }
    }

    /// Feed one full frame's bytes (preamble + header + payload + CRC)
    /// into the HMAC engine and update counters.
    pub fn update(&mut self, frame_bytes: &[u8]) {
        self.mac.update(frame_bytes);
        self.bytes_since_marker = self
            .bytes_since_marker
            .saturating_add(frame_bytes.len() as u64);
        self.frames_since_marker = self.frames_since_marker.saturating_add(1);
    }

    pub fn frames(&self) -> u32 {
        self.frames_since_marker
    }
    pub fn bytes(&self) -> u64 {
        self.bytes_since_marker
    }
    pub fn from_offset(&self) -> u64 {
        self.from_offset
    }

    /// Should the writer emit a marker now?
    pub fn should_emit(&self) -> bool {
        self.frames_since_marker >= MAX_FRAMES_BETWEEN_MARKERS
            || self.bytes_since_marker >= MAX_BYTES_BETWEEN_MARKERS
    }

    /// Finalise the current window: extract the HMAC tag (hex-encoded)
    /// and reset the engine for the next window. Caller writes the
    /// marker frame using the returned values + the current file offset
    /// as `to_offset`.
    pub fn finalise_marker(&mut self, key: &[u8], to_offset: u64) -> MarkerPayload {
        // Steal the existing mac to extract the tag; replace with a
        // fresh engine for the next window.
        let mac = std::mem::replace(
            &mut self.mac,
            HmacSha256::new_from_slice(key).expect("HMAC-SHA256 init"),
        );
        let tag = mac.finalize().into_bytes();
        let hmac_hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        let payload = MarkerPayload {
            from_offset: self.from_offset,
            to_offset,
            frame_count: self.frames_since_marker,
            hmac_hex,
        };
        self.from_offset = to_offset;
        self.bytes_since_marker = 0;
        self.frames_since_marker = 0;
        payload
    }
}

/// Payload of an `EVENT_TYPE_COMPACTION_MARKER` event. Serialised to
/// JSON and written as the marker's payload bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MarkerPayload {
    pub from_offset: u64,
    pub to_offset: u64,
    pub frame_count: u32,
    pub hmac_hex: String,
}

/// Read the operator's HMAC key from `path`. Generates a fresh 32-byte
/// random key on first call and writes it mode 0600 (unix) / icacls
/// grant:r owner (Windows) + DPAPI-wrapped per-user on Windows when
/// available (K-Sec-4).
///
/// On Windows, when an existing key file lacks the `NEOTH_DPAPIv1`
/// magic header (legacy plaintext from pre-K-Sec-4 installs), the bytes
/// are returned as-is so existing markers verify; the next [`rotate`]
/// or fresh-key path re-writes the file in wrapped form. This keeps
/// upgrades zero-downtime for operators with an existing
/// `~/.neoth/wal/hmac.key`.
pub fn load_or_init_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        let body =
            std::fs::read(path).with_context(|| format!("read HMAC key {}", path.display()))?;
        let key_bytes = maybe_unwrap_dpapi(&body, path)?;
        if key_bytes.len() < 16 {
            anyhow::bail!(
                "HMAC key at {} is shorter than 16 bytes; refuse to use weak key",
                path.display()
            );
        }
        return Ok(key_bytes);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create HMAC key parent {}", parent.display()))?;
    }
    // 32 bytes via the OS CSPRNG. **Fail closed** when the OS RNG is
    // unavailable — a weak HMAC key undermines the whole tamper-evidence
    // story, so we'd rather refuse to write than ship a predictable key.
    // Per Codex audit item #3 (post-SP-2 review).
    let mut key = vec![0u8; 32];
    getrandom::getrandom(&mut key)
        .context("OS RNG unavailable — refusing to generate weak HMAC key")?;

    write_key_securely(path, &key)?;
    Ok(key)
}

/// SC-09 Tier-1 recovery: re-wrap an operator-supplied RAW HMAC key for
/// THIS machine/user and install it at `path`, OVERWRITING any existing
/// key file (the typical case: a key DPAPI-bound to a different Windows
/// user/box after a restore, which `load_or_init_key` can no longer
/// unwrap). The raw bytes come from a `neoth security backup-hmac-key`
/// backup taken on the original host. On Windows the bytes are
/// DPAPI-wrapped for the current user before writing (re-binding the
/// restored key to this machine); on unix the file is written mode 0600.
/// Refuses keys shorter than 16 bytes — the same weak-key floor as
/// [`load_or_init_key`].
///
/// Run with the daemon stopped: there is a brief window where the key
/// file is absent between removing the old file and writing the new one.
pub fn rewrap_key(path: &Path, raw_key: &[u8]) -> Result<()> {
    if raw_key.len() < 16 {
        anyhow::bail!(
            "refusing to install HMAC key shorter than 16 bytes ({} given) — \
             a weak key undermines WAL tamper-evidence",
            raw_key.len()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create HMAC key parent {}", parent.display()))?;
    }
    if path.exists() {
        std::fs::remove_file(path).with_context(|| {
            format!(
                "remove existing HMAC key at {} before re-wrap",
                path.display()
            )
        })?;
    }
    write_key_securely(path, raw_key)
}

/// On Windows: if the file is DPAPI-wrapped, unwrap. Otherwise return
/// the bytes unchanged (legacy plaintext path). Linux: always return
/// unchanged.
#[cfg(windows)]
pub(crate) fn maybe_unwrap_dpapi(body: &[u8], path: &Path) -> Result<Vec<u8>> {
    if crate::wal::dpapi::is_wrapped(body) {
        crate::wal::dpapi::unprotect(body)
            .with_context(|| format!("DPAPI-unwrap HMAC key at {}", path.display()))
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(not(windows))]
pub(crate) fn maybe_unwrap_dpapi(body: &[u8], _path: &Path) -> Result<Vec<u8>> {
    Ok(body.to_vec())
}

#[cfg(unix)]
pub(crate) fn write_key_securely(path: &Path, key: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create HMAC key at {} with mode 0600", path.display()))?;
    use std::io::Write;
    file.write_all(key)
        .with_context(|| format!("write HMAC key bytes to {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync HMAC key {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_key_securely(path: &Path, key: &[u8]) -> Result<()> {
    // K-Sec-4: DPAPI-wrap before writing so a copy of the file is
    // useless outside the current Windows user account. If DPAPI is
    // unavailable (no user session, SYSTEM context, …) log a warning
    // and fall back to plaintext + DACL — the file stays as protected
    // as it was pre-K-Sec-4 instead of failing key generation.
    let payload = match crate::wal::dpapi::protect(key) {
        Ok(wrapped) => wrapped,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "DPAPI wrap unavailable; writing HMAC key plaintext with DACL fallback"
            );
            key.to_vec()
        }
    };
    std::fs::write(path, &payload)
        .with_context(|| format!("write HMAC key at {}", path.display()))?;
    if let Err(e) = crate::wal::win_acl::restrict_to_owner(path) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "HMAC key DACL restriction failed; key file inherits parent DACL"
        );
    }
    Ok(())
}

/// Verify a marker against the bytes between `from_offset` and `to_offset`
/// in `segment_path`. Returns `Ok(())` on match, `Err` with a clear
/// message on mismatch.
pub fn verify_marker(segment_path: &Path, key: &[u8], marker: &MarkerPayload) -> Result<()> {
    let raw = std::fs::read(segment_path)
        .with_context(|| format!("read segment {}", segment_path.display()))?;
    // Compaction markers are computed over the UNCOMPRESSED frame stream at
    // logical offsets. A finalized compressed segment (v2 header + zstd blob)
    // stores those frames compressed, so the marker offsets no longer point at
    // raw file bytes — reconstruct the logical (decompressed) bytes first, else
    // `verify` would silently mis-read (false FAIL) or skip (false clean) every
    // compressed segment, defeating the whole tamper-evidence guarantee.
    let (_, logical) = logical_segment_bytes(&raw)
        .with_context(|| format!("reconstruct logical bytes for {}", segment_path.display()))?;
    verify_marker_bytes(&logical, key, marker).map_err(|e| {
        // Preserve the segment-path context the operator needs.
        anyhow::anyhow!("{} in {}", e, segment_path.display())
    })
}

/// Reconstruct a segment's LOGICAL byte layout — the bytes the compaction
/// markers' `from_offset`/`to_offset` index into. For an uncompressed (v1)
/// segment that is just the raw file (borrowed, no copy). For a compressed (v2)
/// segment it is `header || decompress(frame-blob)` — because the marker offsets
/// were computed over the uncompressed frame stream during live operation, and
/// the v2 header length (61) is identical live + finalized (the live segment is
/// already v2 when compression is on), so no offset shift is needed. Returns the
/// header length too, so frame walkers know where the first frame starts.
pub(crate) fn logical_segment_bytes(raw: &[u8]) -> Result<(usize, Cow<'_, [u8]>)> {
    // A file without a parseable segment header — a bare frame stream (minimal
    // test fixture) or a pre-header artifact — is treated as raw, frames starting
    // at offset 0. Only a header that parses AND sets the compression flag
    // triggers decompression; a flagged-compressed header whose blob won't inflate
    // IS an error (tamper-suspect), surfaced to the caller.
    let Ok(hdr) = parse_segment_header(raw) else {
        return Ok((0, Cow::Borrowed(raw)));
    };
    let header_len = hdr.header_len();
    if !hdr.is_compressed() {
        return Ok((header_len, Cow::Borrowed(raw)));
    }
    let blob = raw.get(header_len..).unwrap_or(&[]);
    let frames = decompress_frames(blob).context("decompress segment frame blob")?;
    let mut logical = Vec::with_capacity(header_len + frames.len());
    logical.extend_from_slice(&raw[..header_len]);
    logical.extend_from_slice(&frames);
    Ok((header_len, Cow::Owned(logical)))
}

/// Verify a marker's HMAC against an in-memory LOGICAL segment byte slice (see
/// [`logical_segment_bytes`]). Separated from [`verify_marker`] so the verifier
/// can decompress a compressed segment ONCE and check every marker against the
/// shared reconstruction instead of re-reading + re-decompressing per marker.
pub fn verify_marker_bytes(segment_bytes: &[u8], key: &[u8], marker: &MarkerPayload) -> Result<()> {
    let from = marker.from_offset as usize;
    let to = marker.to_offset as usize;
    if to <= from {
        anyhow::bail!("marker covers zero bytes — refuse to verify empty window");
    }
    let buf = segment_bytes.get(from..to).with_context(|| {
        format!(
            "marker window {from}..{to} out of bounds for a {}-byte logical segment",
            segment_bytes.len()
        )
    })?;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(buf);
    let tag = mac.finalize().into_bytes();
    let computed_hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    if computed_hex != marker.hmac_hex {
        anyhow::bail!(
            "HMAC mismatch ({}..{}): marker={}, computed={}. \
             WAL window may have been tampered with.",
            marker.from_offset,
            marker.to_offset,
            marker.hmac_hex,
            computed_hex,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn should_emit_after_frame_threshold() {
        let mut state = CompactionState::new(b"k", 0);
        for _ in 0..MAX_FRAMES_BETWEEN_MARKERS - 1 {
            state.update(&[0u8; 1]);
            assert!(!state.should_emit());
        }
        state.update(&[0u8; 1]);
        assert!(state.should_emit(), "expected emit after frame threshold");
    }

    #[test]
    fn should_emit_after_byte_threshold() {
        let mut state = CompactionState::new(b"k", 0);
        let big = vec![0u8; (MAX_BYTES_BETWEEN_MARKERS + 1) as usize];
        state.update(&big);
        assert!(state.should_emit());
    }

    #[test]
    fn finalise_resets_window() {
        let key = b"secret";
        let mut state = CompactionState::new(key, 100);
        state.update(b"first frame");
        state.update(b"second frame");
        let marker = state.finalise_marker(key, 250);
        assert_eq!(marker.from_offset, 100);
        assert_eq!(marker.to_offset, 250);
        assert_eq!(marker.frame_count, 2);
        assert_eq!(marker.hmac_hex.len(), 64);

        // After finalise, state is reset.
        assert_eq!(state.frames(), 0);
        assert_eq!(state.bytes(), 0);
        assert_eq!(state.from_offset(), 250);
    }

    #[test]
    fn finalise_produces_deterministic_tag_for_same_input() {
        let key = b"shared-key";
        let mut a = CompactionState::new(key, 0);
        a.update(b"alpha");
        let m_a = a.finalise_marker(key, 5);

        let mut b = CompactionState::new(key, 0);
        b.update(b"alpha");
        let m_b = b.finalise_marker(key, 5);

        assert_eq!(m_a.hmac_hex, m_b.hmac_hex);
    }

    #[test]
    fn different_keys_produce_different_tags() {
        let mut a = CompactionState::new(b"k1", 0);
        a.update(b"x");
        let mut b = CompactionState::new(b"k2", 0);
        b.update(b"x");
        assert_ne!(
            a.finalise_marker(b"k1", 1).hmac_hex,
            b.finalise_marker(b"k2", 1).hmac_hex,
        );
    }

    #[test]
    fn load_or_init_key_generates_on_first_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        assert!(!path.exists());
        let key = load_or_init_key(&path).unwrap();
        assert_eq!(key.len(), 32);
        assert!(path.exists());
        // Second call returns the same key.
        let key2 = load_or_init_key(&path).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn load_or_init_rejects_too_short_existing_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        std::fs::write(&path, b"short").unwrap();
        let r = load_or_init_key(&path);
        assert!(r.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn load_or_init_passes_through_legacy_plaintext_key() {
        // Backward-compat: an existing pre-K-Sec-4 install holds a 32-
        // byte plaintext key. `load_or_init_key` must return those
        // bytes verbatim so existing markers continue to verify.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let legacy = vec![0x42u8; 32];
        std::fs::write(&path, &legacy).unwrap();

        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(
            loaded, legacy,
            "legacy plaintext key must roundtrip unchanged"
        );
    }

    #[cfg(windows)]
    #[test]
    fn fresh_key_is_dpapi_wrapped_on_disk() {
        // K-Sec-4 contract: a freshly-generated key is wrapped on disk.
        // We can't compare the wrapped bytes to anything (DPAPI is
        // non-deterministic) — pin (a) the on-disk bytes carry the
        // NEOTH_DPAPIv1 magic OR (b) DPAPI was unavailable and we
        // fell back to plaintext. Either is a tested branch.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let key = load_or_init_key(&path).unwrap();
        assert_eq!(key.len(), 32);

        let on_disk = std::fs::read(&path).unwrap();
        let wrapped = crate::wal::dpapi::is_wrapped(&on_disk);
        let plaintext_fallback = on_disk == key;
        assert!(
            wrapped || plaintext_fallback,
            "on-disk key must be either DPAPI-wrapped or the plaintext fallback"
        );

        // Second call must return the same logical key regardless of
        // whether DPAPI was used.
        let key2 = load_or_init_key(&path).unwrap();
        assert_eq!(key, key2);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        load_or_init_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rewrap_key_refuses_short_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let err = rewrap_key(&path, b"short").unwrap_err();
        assert!(
            err.to_string().contains("shorter than 16 bytes"),
            "got: {err}"
        );
        assert!(
            !path.exists(),
            "no key file written when the key is rejected"
        );
    }

    #[test]
    fn rewrap_key_roundtrips_via_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        let raw = vec![7u8; 32];
        rewrap_key(&path, &raw).unwrap();
        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(
            loaded, raw,
            "rewrapped key must load back to the same bytes"
        );
    }

    #[test]
    fn rewrap_key_overwrites_existing_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");
        rewrap_key(&path, &[1u8; 32]).unwrap();
        let restored = vec![9u8; 24];
        rewrap_key(&path, &restored).unwrap();
        let loaded = load_or_init_key(&path).unwrap();
        assert_eq!(loaded, restored, "rewrap must overwrite the prior key");
    }

    #[test]
    fn verify_marker_succeeds_on_matching_bytes() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        let key = b"k";
        let frames: &[&[u8]] = &[b"first", b"second", b"third"];

        // Lay down some bytes on disk to emulate frames.
        let mut bytes = Vec::new();
        for f in frames {
            bytes.extend_from_slice(f);
        }
        std::fs::write(&seg_path, &bytes).unwrap();

        // Compute the marker the writer would have emitted.
        let mut state = CompactionState::new(key, 0);
        for f in frames {
            state.update(f);
        }
        let marker = state.finalise_marker(key, bytes.len() as u64);
        verify_marker(&seg_path, key, &marker).expect("matching window verifies");
    }

    #[test]
    fn verify_marker_detects_tamper() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        let key = b"k";
        let original = b"alpha-beta-gamma".to_vec();
        std::fs::write(&seg_path, &original).unwrap();

        let mut state = CompactionState::new(key, 0);
        state.update(&original);
        let marker = state.finalise_marker(key, original.len() as u64);

        // Tamper: flip one byte.
        let mut tampered = original.clone();
        tampered[5] ^= 0x01;
        std::fs::write(&seg_path, &tampered).unwrap();

        let r = verify_marker(&seg_path, key, &marker);
        assert!(r.is_err(), "tampered bytes must fail HMAC check");
        let msg = format!("{r:?}");
        assert!(msg.contains("HMAC mismatch"), "error must explain: {msg}");
    }

    #[test]
    fn verify_marker_works_on_compressed_segment() {
        // The gap this closes: a finalized COMPRESSED (v2 header + zstd blob)
        // segment stores its frames + compaction markers inside the blob, at
        // logical offsets. The old `verify_marker` seeked RAW file bytes → it
        // silently mis-read every compressed segment. `verify_marker` now
        // reconstructs the logical bytes first, so the HMAC check actually runs.
        use crate::wal::HeaderBuilder;
        use crate::wal::compress::compress_frames;
        use crate::wal::events::{EVENT_TYPE_COMPACTION_MARKER, EVENT_TYPE_RAW_TEXT};
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{
            SegmentHeaderV2, SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN,
        };

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let key = b"compression-verify-test-key";
        let from = SEGMENT_HEADER_V2_LEN as u64; // 61 — live segment is already v2 when compressed

        // Build the raw frame stream the writer would hold before compressing:
        // 3 data frames + a COMPACTION_MARKER over them. `tamper` flips a byte in
        // frame 1's payload AND fixes that frame's CRC (so the frame still decodes
        // and the marker after it stays findable) — the marker's pre-tamper HMAC
        // then mismatches, exactly like a post-redaction segment.
        let build_raw = |tamper: bool| -> (Vec<u8>, MarkerPayload) {
            let mut data = Vec::new();
            for p in [b"alpha".as_slice(), b"bravo", b"charlie"] {
                let h = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, p).build();
                data.extend_from_slice(&encode_frame(&h, p));
            }
            let to = from + data.len() as u64;
            let mut state = CompactionState::new(key, from);
            state.update(&data);
            let marker = state.finalise_marker(key, to);
            if tamper {
                let flen = encode_frame(
                    &HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, b"alpha".as_slice()).build(),
                    b"alpha",
                )
                .len();
                data[100] ^= 0x01; // 4 magic + 96 header = first payload byte
                let crc_off = flen - 4;
                let new_crc = crc32c::crc32c(&data[..crc_off]);
                data[crc_off..crc_off + 4].copy_from_slice(&new_crc.to_le_bytes());
            }
            // Append the marker FRAME so it lands inside the compressed blob.
            let mpayload = serde_json::to_vec(&marker).unwrap();
            let mh = HeaderBuilder::new(EVENT_TYPE_COMPACTION_MARKER, &mpayload).build();
            data.extend_from_slice(&encode_frame(&mh, &mpayload));
            (data, marker)
        };
        let write_compressed = |raw: &[u8]| {
            let blob = compress_frames(raw).unwrap();
            let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
            let mut file = hdr.to_le_bytes().to_vec();
            file.extend_from_slice(&blob);
            std::fs::write(&seg, file).unwrap();
        };

        // CLEAN — the compressed segment verifies.
        let (raw_clean, marker) = build_raw(false);
        write_compressed(&raw_clean);
        // logical reconstruction = header + decompressed frames.
        let file = std::fs::read(&seg).unwrap();
        let (hl, logical) = logical_segment_bytes(&file).unwrap();
        assert_eq!(hl, SEGMENT_HEADER_V2_LEN);
        assert_eq!(&logical[hl..], &raw_clean[..], "decompress restores the frame stream");
        verify_marker(&seg, key, &marker).expect("compressed segment verifies clean");

        // TAMPER — a changed byte inside the compressed window now FAILS (no more
        // silent false-clean on compressed segments).
        let (raw_tampered, _) = build_raw(true);
        write_compressed(&raw_tampered);
        let r = verify_marker(&seg, key, &marker);
        assert!(r.is_err(), "tampered compressed window must fail HMAC: {r:?}");
        assert!(format!("{r:?}").contains("HMAC mismatch"), "got: {r:?}");
    }

    #[test]
    fn verify_marker_rejects_zero_byte_window() {
        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        std::fs::write(&seg_path, b"").unwrap();
        let marker = MarkerPayload {
            from_offset: 0,
            to_offset: 0,
            frame_count: 0,
            hmac_hex: "deadbeef".into(),
        };
        let r = verify_marker(&seg_path, b"k", &marker);
        assert!(r.is_err());
    }
}
