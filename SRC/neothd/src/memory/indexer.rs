//! WAL → SQLite indexer.
//!
//! Reads a WAL segment from its last-indexed offset and replays the frames
//! into the views tables. Stateful via the `wal_cursor` table so restart
//! continues where it left off without re-indexing.
//!
//! Run modes:
//! - `replay_once(...)` — single sweep, used by tests and the recall CLI
//!   when it wants up-to-date views before querying.
//! - `tail(...)` — long-running, polls the segment file every interval and
//!   indexes anything new. Spawned by `neoth serve` alongside the WAL writer.
//!
//! Frame format is the one defined by `wal/frame.rs` — magic preamble +
//! 96-byte EventHeaderV2 + reserved + payload + CRC32c. The indexer ignores
//! frames it does not recognise (forward compat); each known event_type
//! INSERTs into the appropriate view.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use tokio::fs;
use tracing::{debug, warn};

use crate::wal::events::{
    EVENT_TYPE_CHANNEL_EGRESS, EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_INDEXER_TAMPER_SUSPECT,
    EVENT_TYPE_PROVIDER_REQUEST, EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_RAW_TEXT,
};
use crate::wal::frame::decode_frame;
use crate::wal::writer::WalWriterHandle;

/// Index every new frame in `segment_path` into `conn`. Returns the number of
/// frames newly indexed.
pub async fn replay_once(conn: &mut Connection, segment_path: &Path) -> Result<usize> {
    replay_once_audited(conn, segment_path, None).await
}

/// GR-164 — like [`replay_once`] but, when `writer` is `Some`, emits a
/// `0x5E INDEXER_TAMPER_SUSPECT` WAL frame if a segment fails to reconstruct
/// (tamper-suspect), so the skip is auditable after the fact. The `tail`
/// daemon loop passes a writer; CLI/test callers use the writerless
/// [`replay_once`].
pub async fn replay_once_audited(
    conn: &mut Connection,
    segment_path: &Path,
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    let segment_key = segment_path.to_string_lossy().to_string();
    let start_offset = load_cursor(conn, &segment_key)?;

    let bytes = match fs::read(segment_path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("read WAL segment {}", segment_path.display())));
        }
    };

    // GOLD-ARCH-03: reconstruct the LOGICAL (decompressed) segment bytes so a
    // v2/zstd-compressed sealed segment's frames are INDEXED, not silently
    // skipped. The prior code skipped a hard-coded 60-byte header and walked
    // the RAW file — for a compressed segment that body is a single zstd blob,
    // so every frame decoded as garbage and the recall views lost ALL events
    // from compacted segments. For v1 this borrows the raw bytes. The saved
    // cursor is a LOGICAL offset, so the resume path (start_offset > 0) indexes
    // from it directly against the same logical byte stream.
    let (header_len, logical) = match crate::wal::compaction::logical_segment_bytes(&bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                error = %e,
                segment = %segment_path.display(),
                "indexer: unreconstructable (tamper-suspect) segment — skipping this pass"
            );
            // GR-164: the monitor cron only scans for already-written recovery
            // frames; this decode-time failure leaves none, so without an
            // explicit frame the tamper event is unauditable. Emit one.
            if let Some(w) = writer {
                emit_tamper_suspect(w, segment_path, &e.to_string()).await;
            }
            return Ok(0);
        }
    };

    // First-time index of this segment starts after the header; a resume picks
    // up from the saved logical cursor. GR-006: a resume cursor must NEVER point
    // INTO the header. A pre-GOLD-ARCH-03 install could have persisted a stale
    // cursor below the real header_len (e.g. 60 against a 61-byte v2 header),
    // which would land `decode_frame` mid-header so the segment makes no progress
    // and its frames never index. Clamp up to `header_len` so a stale/short
    // cursor self-heals to the first real frame; a normal resume cursor (≥
    // header_len) is unchanged.
    let mut offset = start_offset.max(header_len);
    if offset >= logical.len() {
        return Ok(0);
    }

    let tx = conn.transaction().context("begin index transaction")?;
    let mut indexed = 0usize;

    while offset < logical.len() {
        let dec = match decode_frame(&logical[offset..]) {
            Ok(d) => d,
            Err(e) => {
                // Partial frame at the tail (writer mid-append) — stop and
                // resume on next pass. Any other error is a corruption signal.
                debug!(error = %e, offset, "stop indexing at partial/invalid frame");
                break;
            }
        };
        let total_len = dec.header.total_len as usize;
        if total_len == 0 || offset + total_len > logical.len() {
            break;
        }
        index_frame(&tx, &dec, &segment_key)?;
        offset += total_len;
        indexed += 1;
    }

    save_cursor(&tx, &segment_key, offset)?;
    tx.commit().context("commit index transaction")?;
    Ok(indexed)
}

/// Long-running tail loop. Polls **every WAL segment** in the segment's
/// parent directory every `interval` and indexes anything new. Rotation-
/// aware: after `wal/writer` rolls from `000001.wal` to `000002.wal`,
/// this loop picks up the new segment automatically — the per-segment
/// cursor table (`wal_cursor.segment_path` is the PK) keeps each
/// segment's progress isolated.
///
/// Backwards-compatible: `segment_path` still drives discovery — we treat
/// it as a seed file inside the WAL directory and walk every `.wal`
/// sibling. The seed file itself is always indexed even if it does not
/// (yet) exist on disk.
pub async fn tail(
    mut conn: Connection,
    segment_path: PathBuf,
    interval: Duration,
    // GR-164: when `Some`, a tamper-suspect segment emits a 0x5E alert frame.
    writer: Option<WalWriterHandle>,
    // MEMGRAPH-01: when `Some`, episodes indexed this pass are auto-embedded into
    // the vector recall lane (incremental — no manual `--embed-backfill`).
    embed_provider: Option<std::sync::Arc<dyn crate::providers::embed::EmbedProvider>>,
    // GOLD-ADAPT-TRAIL-02: when `Some`, fires `()` on every pass that indexes
    // at least one new frame so in-process consumers (kanban_sse relay) can
    // push updates without polling. Silently discarded when no receiver exists.
    change_tx: Option<tokio::sync::watch::Sender<()>>,
) -> Result<()> {
    loop {
        match replay_all_segments_audited(&mut conn, &segment_path, writer.as_ref()).await {
            Ok(n) if n > 0 => {
                debug!(frames = n, "indexer caught up");
                // GOLD-ADAPT-TRAIL-02 — notify in-process consumers that views.db
                // has new data. watch::Sender coalesces multiple sends into one
                // wakeup for the receiver — correct for "push current state" use.
                // `let _ =` silences the Err when no receiver is connected.
                if let Some(tx) = &change_tx {
                    let _ = tx.send(());
                }
                // MEMGRAPH-01 — auto-embed the new episode(s) this pass added, so
                // the continuous (channel/daemon) ingest joins the vector lane
                // without an operator backfill. Bounded per pass; best-effort.
                // Orchestrated in three phases (sync collect → async embed → sync
                // store) so NO `&Connection` is held across the `.await` — the
                // owned `conn` stays parked (Connection is Send), keeping this
                // spawned tail future `Send`.
                if let Some(p) = embed_provider.as_ref() {
                    let pending = crate::memory::embeddings::pending_episode_texts(&conn, 64);
                    let mut vectors = Vec::with_capacity(pending.len());
                    for (event_id, text) in pending {
                        if let Some((model, vec)) =
                            crate::memory::embeddings::embed_one(&text, p.as_ref()).await
                        {
                            vectors.push((event_id, model, vec));
                        }
                    }
                    let embedded = vectors.len();
                    for (event_id, model, vec) in vectors {
                        crate::memory::embeddings::store_episode_vector(&conn, event_id, &model, &vec);
                    }
                    if embedded > 0 {
                        debug!(embedded, "indexer auto-embedded new episodes (MEMGRAPH-01)");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "indexer pass failed; retrying"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Index every `.wal` file in `seed.parent()` (plus `seed` itself if the
/// parent walk misses it). Each segment maintains its own cursor in
/// `wal_cursor`, so frame ordering within a segment is preserved and
/// rotated-away segments stop accumulating work after their final byte
/// has been indexed once.
///
/// Returns the total number of frames newly indexed across all segments.
pub async fn replay_all_segments(conn: &mut Connection, seed: &Path) -> Result<usize> {
    replay_all_segments_audited(conn, seed, None).await
}

/// GR-164 — writer-aware variant of [`replay_all_segments`]; threads `writer`
/// down to [`replay_once_audited`] so a tamper-suspect segment emits an alert.
async fn replay_all_segments_audited(
    conn: &mut Connection,
    seed: &Path,
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    let mut total = 0usize;
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    // The seed path always counts — even when it does not exist on disk
    // yet (fresh boot before the writer creates 000001.wal). replay_once
    // tolerates missing files by returning Ok(0).
    if seen.insert(seed.to_path_buf()) {
        total += replay_once_audited(conn, seed, writer).await?;
    }

    // Discover sibling segments. Parent missing = nothing to walk; that
    // matches the "no WAL yet" state on first boot.
    let Some(parent) = seed.parent() else {
        return Ok(total);
    };
    let mut rd = match fs::read_dir(parent).await {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(total),
        Err(e) => {
            return Err(
                anyhow::Error::from(e).context(format!("read WAL dir {}", parent.display()))
            );
        }
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    while let Some(entry) = rd.next_entry().await? {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        if seen.insert(p.clone()) {
            paths.push(p);
        }
    }
    // Sort by filename so per-segment cursors advance in segment-seq order.
    paths.sort();
    for p in paths {
        total += replay_once_audited(conn, &p, writer).await?;
    }
    Ok(total)
}

/// GR-164 — append a `0x5E INDEXER_TAMPER_SUSPECT` frame. Best-effort: a WAL
/// failure here must not crash the indexer loop (it logs and moves on).
async fn emit_tamper_suspect(writer: &WalWriterHandle, segment_path: &Path, error: &str) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "segment": segment_path.display().to_string(),
        "error": error,
        "ts_unix": crate::time::now_unix_i64(),
    }))
    .unwrap_or_default();
    let header = crate::wal::make_header(EVENT_TYPE_INDEXER_TAMPER_SUSPECT, &payload);
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "indexer: failed to emit INDEXER_TAMPER_SUSPECT frame");
    }
}

fn load_cursor(conn: &Connection, segment_key: &str) -> Result<usize> {
    let cursor: Option<i64> = conn
        .query_row(
            "SELECT next_offset FROM wal_cursor WHERE segment_path = ?1",
            params![segment_key],
            |r| r.get(0),
        )
        .optional()
        .context("read wal_cursor")?;
    Ok(cursor.unwrap_or(0) as usize)
}

fn save_cursor(tx: &rusqlite::Transaction, segment_key: &str, offset: usize) -> Result<()> {
    tx.execute(
        "INSERT INTO wal_cursor (segment_path, next_offset, updated_ts) VALUES (?1, ?2, ?3) \
         ON CONFLICT(segment_path) DO UPDATE SET next_offset = excluded.next_offset, \
         updated_ts = excluded.updated_ts",
        params![segment_key, offset as i64, now_unix()],
    )
    .context("save wal_cursor")?;
    Ok(())
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

fn index_frame(
    tx: &rusqlite::Transaction,
    dec: &crate::wal::frame::DecodedFrame<'_>,
    segment_key: &str,
) -> Result<()> {
    let header = &dec.header;
    let payload = dec.payload;
    let event_type = header.event_type;
    let event_id = header.event_id.0 as i64;
    let ts_ns = header.hlc.physical_ns() as i64;
    let _ = segment_key;

    match event_type {
        EVENT_TYPE_RAW_TEXT => {
            // GOLD-ADAPT-JV-MEM-11: sanitize before storing — a verbatim-stored
            // prompt-injection / wrapper block could be resurfaced into a future
            // prompt by recall. A payload that is mostly such markup is skipped.
            let raw = std::str::from_utf8(payload).unwrap_or("");
            let cleaned = crate::memory::ingress::sanitize(raw);
            if cleaned.noise {
                tracing::debug!(
                    event_id,
                    noise_ratio = cleaned.noise_ratio,
                    "ingress: RAW_TEXT skipped as injection-noise (JV-MEM-11)"
                );
            } else {
                let text = cleaned.text;
                let text_hash = format!("{:016x}", header.payload_hash);
                // Phase 28a R-22: materialise importance from the WAL header so
                // recall ranking + decay can read it without re-parsing the WAL.
                let importance = header.importance.raw() as f64;
                tx.execute(
                    "INSERT OR IGNORE INTO idx_episode \
                     (event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id, importance, last_access_ts, trust) \
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, ?6, ?7, 2)",
                    params![event_id, event_type as i64, ts_ns, text, text_hash, importance, ts_ns],
                )?;
                // neoth: GOLD-ADAPT-MEMGRAPH-01 — after this tx commits, call
                //   crate::memory::embeddings::embed_episode_text(conn, event_id, &text, provider)
                // from an async context that has an Option<&dyn EmbedProvider>.
                // index_frame is sync (inside a DB transaction) so async embed
                // cannot happen here directly. The tail daemon and any caller
                // with an embed provider should invoke embed_episode_text after
                // replay_once returns.
            }
        }
        EVENT_TYPE_CHANNEL_INGRESS | EVENT_TYPE_CHANNEL_EGRESS => {
            // Channel payloads are JSON with {channel, sender_id, text_*, ...}.
            // Extract for the idx_episode view so recall can search inbound
            // operator messages as if they were RAW_TEXT.
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                let channel = v
                    .get("channel")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                // Prefer the hashed `sender_id_hash` (current frames never carry
                // the plaintext id — it's a phone number for WhatsApp); fall back
                // to legacy `sender_id` so pre-hardening segments still index.
                let sender = v
                    .get("sender_id_hash")
                    .or_else(|| v.get("sender_id"))
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let operator = v
                    .get("operator_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                // INGRESS payload has text_hash + text_bytes but NOT raw text
                // (we hash before storing). For now we record the hash as a
                // searchable token — Day-11b will add a `messages` blob table
                // that keeps the actual prompt body indexed for full-text recall.
                let text_repr = format!(
                    "[{}] {} bytes (hash {:016x})",
                    if event_type == EVENT_TYPE_CHANNEL_INGRESS {
                        "INGRESS"
                    } else {
                        "EGRESS"
                    },
                    v.get(if event_type == EVENT_TYPE_CHANNEL_INGRESS {
                        "text_bytes"
                    } else {
                        "reply_bytes"
                    })
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                    header.payload_hash
                );
                let text_hash = format!("{:016x}", header.payload_hash);
                let importance = header.importance.raw() as f64;
                tx.execute(
                    "INSERT OR IGNORE INTO idx_episode \
                     (event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id, importance, last_access_ts) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        event_id,
                        event_type as i64,
                        ts_ns,
                        text_repr,
                        text_hash,
                        channel,
                        sender,
                        operator,
                        importance,
                        ts_ns
                    ],
                )?;
            }
        }
        EVENT_TYPE_PROVIDER_REQUEST | EVENT_TYPE_PROVIDER_RESPONSE => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                let provider = v
                    .get("provider")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let model = v
                    .get("model")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let text_hash = format!("{:016x}", header.payload_hash);
                let bytes = if event_type == EVENT_TYPE_PROVIDER_REQUEST {
                    v.get("prompt_bytes").and_then(|x| x.as_u64())
                } else {
                    v.get("response_bytes").and_then(|x| x.as_u64())
                };
                let latency = v.get("latency_ns").and_then(|x| x.as_u64());
                let input_tokens = v.get("input_tokens").and_then(|x| x.as_u64());
                let output_tokens = v.get("output_tokens").and_then(|x| x.as_u64());
                tx.execute(
                    "INSERT OR IGNORE INTO idx_provider \
                     (event_id, event_type, ts_ns, provider, model, text_hash, bytes, \
                      latency_ns, input_tokens, output_tokens) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        event_id,
                        event_type as i64,
                        ts_ns,
                        provider,
                        model,
                        text_hash,
                        bytes,
                        latency,
                        input_tokens,
                        output_tokens
                    ],
                )?;
            }
        }
        _ => {
            // Unknown / lifecycle event — skip silently (BOOT, etc.).
        }
    }

    Ok(())
}

// Required for `.optional()` on rusqlite query_row.
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_RAW_TEXT;
    use crate::wal::frame::encode_frame;
    use crate::wal::header::{CRC_LEN, HEADER_BODY_LEN, PREAMBLE_LEN};
    use crate::wal::segment_header::SegmentHeader;
    use crate::wal::{EventFlags, EventHeaderV2, EventId, Hlc, Importance, NodeId, SessionId};
    use tempfile::tempdir;
    use tokio::fs::write;

    fn header_for(event_type: u8, payload_len: u32, event_id: u64, ts_ns: u64) -> EventHeaderV2 {
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len as usize + CRC_LEN) as u32,
            payload_len,
            generation: 0,
            event_id: EventId(event_id),
            hlc: Hlc::new(ts_ns, 0).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: crate::wal::types::WalScope::UNSET,
            category: crate::wal::types::WalCategory::UNSET,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: xxhash_rust::xxh3::xxh3_64(b""),
        }
    }

    #[tokio::test]
    async fn replay_indexes_raw_text_frames() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let db = dir.path().join("views.db");

        // Build a WAL by hand: SegmentHeader + 2 RAW_TEXT frames.
        let mut bytes = Vec::new();
        let sh = SegmentHeader::new(0, 1, 0, 1_700_000_000_000_000_000, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        let p1 = b"hello world".to_vec();
        let h1 = header_for(
            EVENT_TYPE_RAW_TEXT,
            p1.len() as u32,
            1,
            1_700_000_000_000_000_001,
        );
        bytes.extend_from_slice(&encode_frame(&h1, &p1));
        let p2 = b"goodbye moon".to_vec();
        let h2 = header_for(
            EVENT_TYPE_RAW_TEXT,
            p2.len() as u32,
            2,
            1_700_000_000_000_000_002,
        );
        bytes.extend_from_slice(&encode_frame(&h2, &p2));
        write(&seg, &bytes).await.unwrap();

        let mut conn = crate::memory::store::open(&db).unwrap();
        let n = replay_once(&mut conn, &seg).await.unwrap();
        assert_eq!(n, 2, "should index 2 RAW_TEXT frames");

        // Verify rows are present.
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);

        let text1: String = conn
            .query_row("SELECT text FROM idx_episode WHERE event_id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(text1, "hello world");

        // Re-running replay must NOT double-insert (cursor advanced).
        let n2 = replay_once(&mut conn, &seg).await.unwrap();
        assert_eq!(n2, 0);
        let count2: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count2, 2);
    }

    /// GOLD-ADAPT-TRAIL-02 — integration test: tail() must fire change_tx
    /// after indexing at least one new WAL frame so in-process consumers
    /// (kanban_sse relay) wake without polling views.db themselves.
    #[tokio::test]
    async fn trail02_change_bus_fires_after_indexer_replay() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let db = dir.path().join("views.db");

        // Build a minimal WAL segment with one RAW_TEXT frame so the indexer
        // has something to replay (n > 0) on the first pass.
        let mut bytes = Vec::new();
        let sh =
            crate::wal::segment_header::SegmentHeader::new(0, 1, 0, 1_700_000_000_000_000_000, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        let p = b"trail02".to_vec();
        let h = header_for(EVENT_TYPE_RAW_TEXT, p.len() as u32, 42, 1_700_000_042_000_000_000);
        bytes.extend_from_slice(&encode_frame(&h, &p));
        write(&seg, &bytes).await.unwrap();

        let conn = crate::memory::store::open(&db).unwrap();
        let (tx, mut rx) = crate::memory::change_bus::channel();

        // Spawn tail() with a very short interval so the first pass fires quickly.
        let seg_clone = seg.clone();
        let handle = tokio::spawn(async move {
            let _ = crate::memory::indexer::tail(
                conn,
                seg_clone,
                std::time::Duration::from_millis(50),
                None,  // no writer
                None,  // no embed provider
                Some(tx),
            )
            .await;
        });

        // The change-bus receiver must see at least one notification within 2s.
        let changed =
            tokio::time::timeout(std::time::Duration::from_secs(2), rx.changed()).await;
        assert!(
            changed.is_ok(),
            "TRAIL-02: change_tx must fire after the indexer replays a WAL frame"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn replay_indexes_frames_from_a_v2_compressed_segment() {
        // GOLD-ARCH-03 regression: a finalized v2 (zstd-compressed) segment
        // must have its frames indexed. Before the fix, replay_once skipped a
        // hard-coded 60-byte header and walked the raw zstd blob, indexing ZERO
        // frames — the recall views silently lost every event in compacted
        // segments. This test FAILS pre-fix (n == 0) and passes post-fix.
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000007.wal");
        let db = dir.path().join("views.db");

        // The frame stream (what a live v2 segment holds uncompressed).
        let mut frames = Vec::new();
        let p1 = b"compressed hello".to_vec();
        frames.extend_from_slice(&encode_frame(
            &header_for(
                EVENT_TYPE_RAW_TEXT,
                p1.len() as u32,
                11,
                1_700_000_000_000_000_011,
            ),
            &p1,
        ));
        let p2 = b"compressed world".to_vec();
        frames.extend_from_slice(&encode_frame(
            &header_for(
                EVENT_TYPE_RAW_TEXT,
                p2.len() as u32,
                12,
                1_700_000_000_000_000_012,
            ),
            &p2,
        ));

        // Finalize as a v2 compressed segment: 61-byte header + zstd(frames).
        let blob = compress_frames(&frames).unwrap();
        let hdr = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg_bytes = hdr.to_le_bytes().to_vec();
        seg_bytes.extend_from_slice(&blob);
        write(&seg, &seg_bytes).await.unwrap();

        let mut conn = crate::memory::store::open(&db).unwrap();
        let n = replay_once(&mut conn, &seg).await.unwrap();
        assert_eq!(n, 2, "both frames inside the zstd blob must be indexed");
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let text: String = conn
            .query_row(
                "SELECT text FROM idx_episode WHERE event_id = 12",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(text, "compressed world");
        // Re-poll: a sealed compressed segment yields nothing new.
        assert_eq!(replay_once(&mut conn, &seg).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn replay_self_heals_a_stale_cursor_below_header_len() {
        // GR-006 regression: a pre-GOLD-ARCH-03 install could have persisted a
        // wal_cursor BELOW the real header_len (e.g. 60 against a 61-byte v2
        // header). That lands `decode_frame` mid-header → the segment makes no
        // progress and its frames never index (perpetual no-progress). After the
        // fix, replay_once clamps the resume cursor up to header_len and indexes
        // the frames. FAILS pre-fix (n == 0, stuck), passes post-fix.
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000009.wal");
        let db = dir.path().join("views.db");

        let mut frames = Vec::new();
        let p1 = b"stale-cursor hello".to_vec();
        frames.extend_from_slice(&encode_frame(
            &header_for(
                EVENT_TYPE_RAW_TEXT,
                p1.len() as u32,
                21,
                1_700_000_000_000_000_021,
            ),
            &p1,
        ));
        let p2 = b"stale-cursor world".to_vec();
        frames.extend_from_slice(&encode_frame(
            &header_for(
                EVENT_TYPE_RAW_TEXT,
                p2.len() as u32,
                22,
                1_700_000_000_000_000_022,
            ),
            &p2,
        ));
        let blob = compress_frames(&frames).unwrap();
        let hdr = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg_bytes = hdr.to_le_bytes().to_vec();
        seg_bytes.extend_from_slice(&blob);
        write(&seg, &seg_bytes).await.unwrap();

        let mut conn = crate::memory::store::open(&db).unwrap();
        // Plant a STALE cursor at 60 — one byte INTO the 61-byte v2 header.
        let key = seg.to_string_lossy().to_string();
        conn.execute(
            "INSERT INTO wal_cursor (segment_path, next_offset, updated_ts) VALUES (?1, 60, 0)",
            [key.as_str()],
        )
        .unwrap();

        let n = replay_once(&mut conn, &seg).await.unwrap();
        assert_eq!(
            n, 2,
            "a stale cursor below header_len must self-heal and index both frames"
        );
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn replay_on_missing_segment_is_zero() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("does-not-exist.wal");
        let db = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&db).unwrap();
        let n = replay_once(&mut conn, &seg).await.unwrap();
        assert_eq!(n, 0);
    }

    /// Codex-flagged blocker: after the writer rotates from 000001.wal
    /// to 000002.wal, the indexer must still pick up new frames in the
    /// fresh segment. `replay_all_segments` walks every `.wal` sibling
    /// of the seed and advances each segment's own cursor.
    #[tokio::test]
    async fn replay_all_segments_indexes_rotated_pair() {
        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg1 = wal_dir.join("000001.wal");
        let seg2 = wal_dir.join("000002.wal");
        let db = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&db).unwrap();

        // Seg 1: header + one RAW_TEXT frame.
        let mut s1 = Vec::new();
        s1.extend_from_slice(&SegmentHeader::new(0, 1, 0, 0, [0u8; 16]).to_le_bytes());
        let p1 = b"in segment one".to_vec();
        let h1 = header_for(
            EVENT_TYPE_RAW_TEXT,
            p1.len() as u32,
            1,
            1_700_000_000_000_000_001,
        );
        s1.extend_from_slice(&encode_frame(&h1, &p1));
        tokio::fs::write(&seg1, &s1).await.unwrap();

        // Seg 2: header (sequence 2) + one RAW_TEXT frame.
        let mut s2 = Vec::new();
        s2.extend_from_slice(&SegmentHeader::new(1, 2, 2, 0, [0u8; 16]).to_le_bytes());
        let p2 = b"in segment two".to_vec();
        let h2 = header_for(
            EVENT_TYPE_RAW_TEXT,
            p2.len() as u32,
            2,
            1_700_000_000_000_000_002,
        );
        s2.extend_from_slice(&encode_frame(&h2, &p2));
        tokio::fs::write(&seg2, &s2).await.unwrap();

        // Pass the seed = seg1 — replay_all_segments must discover seg2 too.
        let n = replay_all_segments(&mut conn, &seg1).await.unwrap();
        assert_eq!(n, 2, "both segments should be indexed");

        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);

        // Re-running must NOT double-insert per-segment.
        let n2 = replay_all_segments(&mut conn, &seg1).await.unwrap();
        assert_eq!(n2, 0);
    }

    #[tokio::test]
    async fn replay_all_segments_handles_missing_wal_dir() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("nope").join("000001.wal");
        let db = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&db).unwrap();
        // Missing parent dir → no-op, not an error.
        let n = replay_all_segments(&mut conn, &seg).await.unwrap();
        assert_eq!(n, 0);
    }
}
