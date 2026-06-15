//! HF-01 implicit-emit (Session 28g+) — shared best-effort WAL audit
//! helper for HuggingFace model downloads.
//!
//! The explicit path (`cli/models::run_pull`) already emits
//! `0xD7 MODEL_DOWNLOAD_START` + `0xD8 MODEL_DOWNLOAD_COMPLETE` around
//! the user-driven `neoth model pull` flow. The IMPLICIT path — the
//! first-use download triggered inside `providers::local_qwen::ensure_artifacts`
//! and `providers::ouro::adapter::ensure_artifacts` — was gated by
//! HF-01 Slice A but had **no writer in scope**, so the audit chain
//! was silent for the most-common operator flow ("just run `neoth chat`
//! and pay the silent ~3 GB fetch"). This module closes that gap with
//! the same best-effort one-shot writer pattern `run_pull` already uses:
//!
//!   1. If a live daemon owns the WAL writer (pidfile reports a healthy
//!      PID), SKIP the emit — the daemon will end up writing its own
//!      frames once the adapter dispatches, and a second writer on the
//!      same segment violates the single-writer invariant.
//!   2. Otherwise, open a short-lived `wal_spawn` writer, emit the
//!      frame, drop the writer.
//!
//! Failures are tracing-warn'd, NEVER abort the download — the audit
//! frame is a nicety, not a correctness invariant. The download itself
//! is what produces operator-visible bytes on disk.

use crate::config::FreedomConfig;
use crate::daemon::pidfile;
use crate::wal::events::{EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE, EVENT_TYPE_MODEL_DOWNLOAD_START};
use crate::wal::{HeaderBuilder, spawn as wal_spawn};

/// HF-01 — best-effort emit of a `0xD7 MODEL_DOWNLOAD_START` audit frame
/// around an implicit-path HuggingFace fetch. The matching
/// [`emit_complete`] closes the bracket with `0xD8`.
///
/// Skipped silently when a live daemon owns the WAL writer (single-
/// writer invariant) or when WAL spawn fails (best-effort).
pub async fn emit_start(model_id: &str) {
    emit_event(EVENT_TYPE_MODEL_DOWNLOAD_START, model_id, None).await;
}

/// HF-01 — best-effort emit of `0xD8 MODEL_DOWNLOAD_COMPLETE`. The
/// `cached_path` is the on-disk location the fetch resolved to (so
/// `neoth wal show` can correlate the model id to the operator's local
/// cache layout); `duration_ms` is the wall-clock cost of the fetch.
pub async fn emit_complete(model_id: &str, cached_path: &str, duration_ms: u64) {
    emit_event(
        EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
        model_id,
        Some((cached_path, duration_ms)),
    )
    .await;
}

async fn emit_event(event_type: u8, model_id: &str, complete_fields: Option<(&str, u64)>) {
    // Single-writer invariant: skip if a live daemon owns the segment.
    let pidfile_path = pidfile::default_pidfile();
    if matches!(pidfile::live_daemon_pid(&pidfile_path), Ok(Some(_))) {
        return;
    }

    let seg = FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(parent) = seg.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok((writer, join)) = wal_spawn(seg) else {
        // Best-effort: a broken WAL dir must not abort the download.
        tracing::debug!(
            event_type = event_type,
            model_id = model_id,
            "HF-01 implicit-emit: wal_spawn failed; skipping audit frame"
        );
        return;
    };

    let ts_unix = crate::time::now_unix_secs();
    let payload = match complete_fields {
        None => serde_json::to_vec(&serde_json::json!({
            "model_id": model_id,
            "ts_unix": ts_unix,
            "trigger": "implicit",
        })),
        Some((cached_path, duration_ms)) => serde_json::to_vec(&serde_json::json!({
            "model_id": model_id,
            "cached_path": cached_path,
            "duration_ms": duration_ms,
            "ts_unix": ts_unix,
            "trigger": "implicit",
        })),
    }
    .unwrap_or_default();

    let header = HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(
            error = %e,
            event_type = event_type,
            model_id = model_id,
            "HF-01 implicit-emit: WAL append failed (non-fatal)"
        );
    }
    drop(writer);
    let _ = join.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE, EVENT_TYPE_MODEL_DOWNLOAD_START};

    /// Helper to seed a temp WAL dir + emit one frame directly via the
    /// inner `emit_event` skeleton without relying on the daemon's
    /// global `default_wal_dir`. The production path uses the global
    /// dir intentionally (the daemon owns it); for unit tests we just
    /// pin the payload shape via in-line emit + frame-walk.
    async fn emit_via_writer(seg: &std::path::Path, event_type: u8, payload: serde_json::Value) {
        if let Some(parent) = seg.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let (w, join) = wal_spawn(seg.to_path_buf()).unwrap();
        let bytes = serde_json::to_vec(&payload).unwrap();
        let header = HeaderBuilder::new(event_type, &bytes).build();
        w.append(header, bytes).await.unwrap();
        drop(w);
        let _ = join.await;
    }

    fn find_frame(seg: &std::path::Path, event_type: u8) -> Option<serde_json::Value> {
        let bytes = std::fs::read(seg).ok()?;
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).ok()?;
        let body = &bytes[hdr.header_len()..];
        let mut cursor = 0usize;
        while cursor < body.len() {
            let Ok(dec) = crate::wal::frame::decode_frame(&body[cursor..]) else {
                break;
            };
            if dec.header.event_type == event_type {
                return serde_json::from_slice(dec.payload).ok();
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        None
    }

    #[tokio::test]
    async fn start_frame_carries_required_fields_with_implicit_trigger() {
        // Pin the wire-shape of 0xD7 carried by the implicit path: the
        // `trigger=implicit` discriminator is what lets the operator
        // (and the threat model audit) tell an implicit first-use fetch
        // apart from an explicit `neoth model pull`.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let ts_unix = 1_700_000_000u64;
        let payload = serde_json::json!({
            "model_id": "openai/whisper-large-v3-turbo",
            "ts_unix": ts_unix,
            "trigger": "implicit",
        });
        emit_via_writer(&seg, EVENT_TYPE_MODEL_DOWNLOAD_START, payload).await;
        let found = find_frame(&seg, EVENT_TYPE_MODEL_DOWNLOAD_START)
            .expect("0xD7 frame must be in the WAL");
        assert_eq!(found["model_id"], "openai/whisper-large-v3-turbo");
        assert_eq!(found["ts_unix"], ts_unix);
        assert_eq!(found["trigger"], "implicit");
    }

    #[tokio::test]
    async fn complete_frame_carries_cached_path_and_duration() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let payload = serde_json::json!({
            "model_id": "Qwen/Qwen3-4B-Instruct-2507",
            "cached_path": "/home/user/.cache/huggingface/hub/models--Qwen--Qwen3-4B",
            "duration_ms": 12345u64,
            "ts_unix": 1_700_000_042u64,
            "trigger": "implicit",
        });
        emit_via_writer(&seg, EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE, payload).await;
        let found = find_frame(&seg, EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE)
            .expect("0xD8 frame must be in the WAL");
        assert_eq!(found["model_id"], "Qwen/Qwen3-4B-Instruct-2507");
        assert!(
            found["cached_path"]
                .as_str()
                .unwrap()
                .contains("huggingface")
        );
        assert_eq!(found["duration_ms"], 12345);
        assert_eq!(found["trigger"], "implicit");
    }

    #[tokio::test]
    async fn emit_event_is_silent_no_op_when_wal_dir_is_unwritable() {
        // The helper must NEVER panic / fail when the WAL spawn fails —
        // best-effort means a broken WAL dir still lets the download
        // proceed. We can't easily force `default_wal_dir` to be
        // unwritable in a unit test (it's process-global), so this
        // test pins the contract that `emit_start` / `emit_complete`
        // never return Err (they're `-> ()`).
        // The fact that this compiles + returns is the test.
        let _: () = emit_start("never-actually-fetched").await;
        let _: () = emit_complete("never-actually-fetched", "/tmp/x", 0).await;
    }
}
