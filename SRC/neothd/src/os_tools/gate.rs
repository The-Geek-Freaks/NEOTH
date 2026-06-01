//! PC-01 three-layer OS file-read gate: allowlist → autonomy → read + audit.

use std::path::Path;

use std::path::PathBuf;

use crate::config::OsToolsConfig;
use crate::os_tools::allowlist::{AllowlistError, resolve_within_allowlist, resolve_write_target};
use crate::os_tools::read::read_file_text;
use crate::os_tools::write::write_file_atomic;
use crate::permissions::{Action, AutonomyLevel, Decision, evaluate};
use crate::wal::events::{
    EVENT_TYPE_OS_FILE_DENIED, EVENT_TYPE_OS_FILE_READ, EVENT_TYPE_OS_FILE_WRITE,
    EVENT_TYPE_OS_FILE_WRITE_DENIED,
};
use crate::wal::writer::WalWriterHandle;

#[derive(Debug, thiserror::Error)]
pub enum OsGateError {
    #[error("OS file access denied (allowlist): {0}")]
    Allowlist(#[from] AllowlistError),
    #[error("OS file access denied by autonomy policy: {0}")]
    Denied(String),
    #[error("OS file access requires operator confirm (no interactive surface here): {0}")]
    ConfirmRequired(String),
    #[error("OS file read failed after gate passed: {0}")]
    ReadFailed(String),
    /// PC-01 write slice: the write content exceeds `max_write_bytes`.
    #[error("OS file write denied: {0}")]
    WriteTooLarge(String),
    /// PC-01 write slice: the write failed after the gate passed (IO error).
    #[error("OS file write failed after gate passed: {0}")]
    WriteFailed(String),
}

/// The complete gated read: allowlist-validate `target`, run the autonomy
/// gate, read the (size-capped, UTF-8) file, and emit the WAL audit frame.
/// Returns the file text on success.
///
/// Every outcome is audited when `writer` is `Some`: `0xA8 OS_FILE_READ`
/// (with byte count) on success, `0xA9 OS_FILE_DENIED` (with reason) on any
/// allowlist / autonomy / read failure. `writer` is `None` only in contexts
/// that don't own a WAL writer (the daemon-single-writer rule); the read
/// itself is gated identically either way.
pub async fn read_os_file(
    target: &Path,
    cfg: &OsToolsConfig,
    autonomy: AutonomyLevel,
    writer: Option<&WalWriterHandle>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    // Layer 1 — allowlist + traversal (fail-closed).
    let canonical = match resolve_within_allowlist(target, &cfg.allowed_paths) {
        Ok(c) => c,
        Err(e) => {
            emit_denied(
                writer,
                &target.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate (the path is already allowlist-validated).
    let action = Action::OsFileRead {
        path: canonical.clone(),
    };
    match evaluate(&action, autonomy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_denied(writer, &canonical.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            // The OS-tool path has no TTY/operator prompt — a Confirm
            // verdict (Strict) fails closed, audited, with the reason.
            emit_denied(
                writer,
                &canonical.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — read + audit.
    match read_file_text(&canonical, cfg.max_read_bytes) {
        Ok(text) => {
            emit_read(
                writer,
                &canonical.display().to_string(),
                text.len(),
                now_unix,
            )
            .await;
            Ok(text)
        }
        Err(e) => {
            emit_denied(
                writer,
                &canonical.display().to_string(),
                &format!("read-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::ReadFailed(e.to_string()))
        }
    }
}

/// The complete gated WRITE (PC-01 write slice): size-cap → write-allowlist →
/// autonomy gate (Strict deny / Standard confirm / Elevated+Full allow) →
/// atomic write → WAL audit (`0xAA OS_FILE_WRITE` on success, `0xAB
/// OS_FILE_WRITE_DENIED` on any refusal/failure). Returns the resolved path
/// written on success.
pub async fn write_os_file(
    target: &Path,
    contents: &[u8],
    cfg: &OsToolsConfig,
    autonomy: AutonomyLevel,
    writer: Option<&WalWriterHandle>,
    now_unix: i64,
) -> Result<PathBuf, OsGateError> {
    // Layer 0 — size cap BEFORE any path work (cheap reject of an oversize write).
    if contents.len() > cfg.max_write_bytes {
        let reason = format!(
            "content {} bytes exceeds max_write_bytes {}",
            contents.len(),
            cfg.max_write_bytes
        );
        emit_write_denied(writer, &target.display().to_string(), &reason, now_unix).await;
        return Err(OsGateError::WriteTooLarge(reason));
    }

    // Layer 1 — write-allowlist (canonical parent under allowed_write_paths;
    // symlink-escape + traversal rejected; fail-closed).
    let resolved = match resolve_write_target(target, &cfg.allowed_write_paths) {
        Ok(p) => p,
        Err(e) => {
            emit_write_denied(writer, &target.display().to_string(), &e.to_string(), now_unix).await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate.
    let action = Action::OsFileWrite {
        path: resolved.clone(),
    };
    match evaluate(&action, autonomy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_write_denied(writer, &resolved.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_write_denied(
                writer,
                &resolved.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — atomic write + audit. `existed` records whether we overwrote.
    let existed = resolved.exists();
    match write_file_atomic(&resolved, contents) {
        Ok(()) => {
            emit_write(
                writer,
                &resolved.display().to_string(),
                contents.len(),
                existed,
                now_unix,
            )
            .await;
            Ok(resolved)
        }
        Err(e) => {
            emit_write_denied(
                writer,
                &resolved.display().to_string(),
                &format!("write-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::WriteFailed(e.to_string()))
        }
    }
}

async fn emit_write(
    writer: Option<&WalWriterHandle>,
    path: &str,
    bytes: usize,
    existed: bool,
    ts_unix: i64,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "existed": existed,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OS_FILE_WRITE, &payload).build();
    let _ = w.append(header, payload).await;
}

async fn emit_write_denied(
    writer: Option<&WalWriterHandle>,
    path: &str,
    reason: &str,
    ts_unix: i64,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OS_FILE_WRITE_DENIED, &payload).build();
    let _ = w.append(header, payload).await;
}

async fn emit_read(writer: Option<&WalWriterHandle>, path: &str, bytes: usize, ts_unix: i64) {
    let Some(w) = writer else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OS_FILE_READ, &payload).build();
    let _ = w.append(header, payload).await;
}

async fn emit_denied(writer: Option<&WalWriterHandle>, path: &str, reason: &str, ts_unix: i64) {
    let Some(w) = writer else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_OS_FILE_DENIED, &payload).build();
    let _ = w.append(header, payload).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn cfg_for(dir: &Path) -> OsToolsConfig {
        OsToolsConfig {
            allowed_paths: vec![dir.to_path_buf()],
            max_read_bytes: 1024 * 1024,
            allowed_write_paths: vec![dir.to_path_buf()],
            max_write_bytes: 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn write_allowlisted_file_at_elevated_then_read_back() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("out.txt");
        let cfg = cfg_for(dir.path());
        // Elevated ⇒ OsFileWrite is Allow.
        let resolved = write_os_file(&f, b"written", &cfg, AutonomyLevel::Elevated, None, 0)
            .await
            .expect("elevated write under allowlist must succeed");
        assert!(resolved.ends_with("out.txt"));
        assert_eq!(fs::read(&f).unwrap(), b"written");
    }

    #[tokio::test]
    async fn write_denied_at_standard_no_tty() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        // Standard ⇒ OsFileWrite is Confirm ⇒ no TTY ⇒ ConfirmRequired.
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Standard,
            None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn write_denied_at_strict() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Strict,
            None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::Denied(_))));
    }

    #[tokio::test]
    async fn write_deny_all_when_no_write_allowlist() {
        let dir = tempdir().unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![dir.path().to_path_buf()],
            max_read_bytes: 1024,
            allowed_write_paths: vec![], // deny-all writes
            max_write_bytes: 1024,
        };
        let r = write_os_file(&dir.path().join("x.txt"), b"y", &cfg, AutonomyLevel::Full, None, 0)
            .await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn write_too_large_is_rejected() {
        let dir = tempdir().unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![dir.path().to_path_buf()],
            max_read_bytes: 1024,
            allowed_write_paths: vec![dir.path().to_path_buf()],
            max_write_bytes: 4,
        };
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"way too long",
            &cfg,
            AutonomyLevel::Full,
            None,
            0,
        )
        .await;
        assert!(matches!(r, Err(OsGateError::WriteTooLarge(_))));
    }

    #[tokio::test]
    async fn reads_allowlisted_file_at_standard() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"hello-os").unwrap();
        let cfg = cfg_for(dir.path());
        let text = read_os_file(&f, &cfg, AutonomyLevel::Standard, None, 0)
            .await
            .unwrap();
        assert_eq!(text, "hello-os");
    }

    #[tokio::test]
    async fn deny_all_when_no_allowlist() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![],
            max_read_bytes: 1024,
            allowed_write_paths: vec![],
            max_write_bytes: 1024,
        };
        let r = read_os_file(&f, &cfg, AutonomyLevel::Full, None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn traversal_is_denied_even_at_full() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let evil = dir.path().join("..").join("etc").join("passwd");
        let r = read_os_file(&evil, &cfg, AutonomyLevel::Full, None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::TraversalDetected))
        ));
    }

    #[tokio::test]
    async fn strict_confirms_then_fails_closed() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = cfg_for(dir.path());
        // Strict ⇒ OsFileRead is Confirm ⇒ no TTY here ⇒ ConfirmRequired.
        let r = read_os_file(&f, &cfg, AutonomyLevel::Strict, None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn emits_read_frame_via_writer() {
        use crate::wal::events::EVENT_TYPE_OS_FILE_READ;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"audited").unwrap();
        let cfg = cfg_for(dir.path());

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            Some(&writer),
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_FILE_READ);
        let v: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(v["bytes"], 7);
    }

    #[tokio::test]
    async fn emits_denied_frame_on_deny_all() {
        use crate::wal::events::EVENT_TYPE_OS_FILE_DENIED;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"x").unwrap();
        let cfg = OsToolsConfig {
            allowed_paths: vec![],
            max_read_bytes: 1024,
            allowed_write_paths: vec![],
            max_write_bytes: 1024,
        };
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let _ = read_os_file(&f, &cfg, AutonomyLevel::Full, Some(&writer), 0).await;
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_FILE_DENIED);
    }
}
