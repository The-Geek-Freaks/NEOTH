//! PC-01 three-layer OS file-read gate: allowlist → autonomy → read + audit.

use std::path::Path;

use std::path::PathBuf;

use crate::config::OsToolsConfig;
use crate::os_tools::allowlist::{
    AllowlistError, resolve_exec_program, resolve_within_allowlist, resolve_write_target,
};
use crate::os_tools::launch::launch_program;
use crate::os_tools::read::read_file_text;
use crate::os_tools::write::write_file_atomic;
#[cfg(test)]
use crate::permissions::AutonomyLevel;
use crate::permissions::{Action, Decision, PolicyArgument, evaluate};
use crate::wal::events::{
    EVENT_TYPE_OS_APP_LAUNCH, EVENT_TYPE_OS_APP_LAUNCH_DENIED, EVENT_TYPE_OS_FILE_DENIED,
    EVENT_TYPE_OS_FILE_READ, EVENT_TYPE_OS_FILE_WRITE, EVENT_TYPE_OS_FILE_WRITE_DENIED,
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
    /// PC-01 app-launch slice: the spawn failed after the gate passed (the
    /// binary vanished between resolution and spawn, exec perms, ENOMEM, …).
    #[error("OS app launch failed after gate passed: {0}")]
    LaunchFailed(String),
    /// PC-01 clipboard slice: the OS clipboard backend could not be opened —
    /// almost always a headless host with no display/clipboard server. The
    /// action is gated + audited (`0xBD`) exactly like any other refusal; this
    /// just distinguishes "policy refused" from "no backend here".
    #[error("OS clipboard backend unavailable (headless / no display?): {0}")]
    ClipboardUnavailable(String),
    /// PC-01 clipboard slice: a clipboard WRITE was refused because its content
    /// contains a newline/CR — the terminal auto-execute precondition of a
    /// pastejacking attack — and `tools.os.clipboard.allow_newlines_in_write` is
    /// off (the default). Fires structurally, BEFORE the autonomy gate.
    #[error("OS clipboard write denied (pastejacking guard): {0}")]
    PastejackingPattern(String),
    /// PC-01 clipboard slice: the clipboard content read back exceeds
    /// `max_clipboard_read_bytes`. Surfaced as a refusal (no oversize content is
    /// returned to the caller).
    #[error("OS clipboard read denied: {0}")]
    ReadTooLarge(String),
}

/// Where a gated OS-tool action sends its WAL audit frame. Replaces the old
/// `Option<&WalWriterHandle>` so a one-shot CLI running while `neoth serve`
/// owns the single writer can still get its frame audited — by FORWARDING it
/// to the daemon over the same-user OS audit-RPC channel (AUDIT-RPC-01) instead of
/// silently dropping it.
#[derive(Clone, Copy)]
pub enum AuditSink<'a> {
    /// No audit (the action is still gated; the frame is simply not recorded).
    None,
    /// Append directly to a WAL writer this process owns (the daemon itself, or
    /// a one-shot CLI when no daemon is live).
    Writer(&'a WalWriterHandle),
    /// Append to a one-shot writer and retain the first append failure for the
    /// caller to enforce according to its configured required-audit posture.
    ///
    /// The gated action still returns its ordinary domain result. This keeps
    /// optional audit best-effort while allowing required CLI surfaces to
    /// refuse a false success after the action and writer finalization finish.
    TrackedWriter {
        writer: &'a WalWriterHandle,
        status: &'a AuditStatus,
    },
    /// Forward the frame to the live daemon's audit-RPC listener. `home` is the
    /// neoth home dir (used to find the sidecar + token). Best-effort: if the
    /// daemon/sidecar is unavailable the frame is dropped (same availability
    /// tradeoff as `None`), but the action already ran gated.
    DaemonRpc(&'a Path),
    /// Forward to the daemon and retain an exact acknowledgement failure for a
    /// required-audit caller. This closes the gap between a successful
    /// pre-flight probe and the later event dispatch.
    TrackedDaemonRpc {
        home: &'a Path,
        status: &'a AuditStatus,
    },
}

#[derive(Debug, Default)]
pub struct AuditStatus {
    first_failure: std::sync::Mutex<Option<String>>,
}

impl AuditStatus {
    fn record(&self, error: &crate::wal::error::WalError) {
        self.record_message(error.to_string());
    }

    fn record_message(&self, error: String) {
        let mut first_failure = self
            .first_failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if first_failure.is_none() {
            *first_failure = Some(error);
        }
    }

    pub fn failure(&self) -> Option<String> {
        self.first_failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

/// Send one audit frame to the chosen sink. Single source of truth for the
/// local-append vs daemon-forward dispatch — the per-event `emit_*` helpers
/// build the payload, this routes it.
async fn dispatch_frame(sink: AuditSink<'_>, event_type: u8, payload: Vec<u8>) {
    match sink {
        AuditSink::None => {}
        AuditSink::Writer(w) => {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let _ = w.append(header, payload).await;
        }
        AuditSink::TrackedWriter { writer, status } => {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            if let Err(error) = writer.append(header, payload).await {
                status.record(&error);
            }
        }
        AuditSink::DaemonRpc(home) => {
            // Same-user OS IPC to the WAL-owning daemon. Best-effort: a disabled
            // audit route or unreachable listener means the frame isn't
            // recorded (the action itself already happened, gated).
            if let Err(e) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
            {
                tracing::debug!(error = %e, event_type, "audit-RPC forward failed; frame not recorded");
            }
        }
        AuditSink::TrackedDaemonRpc { home, status } => {
            if let Err(error) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
            {
                status.record_message(error.to_string());
            }
        }
    }
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
pub async fn read_os_file<P: PolicyArgument>(
    target: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    // Layer 1 — allowlist + traversal (fail-closed).
    let canonical = match resolve_within_allowlist(target, &cfg.allowed_paths) {
        Ok(c) => c,
        Err(e) => {
            emit_denied(
                sink,
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
    match evaluate(&action, policy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_denied(sink, &canonical.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            // The OS-tool path has no TTY/operator prompt — a Confirm
            // verdict (Strict) fails closed, audited, with the reason.
            emit_denied(
                sink,
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
            emit_read(sink, &canonical.display().to_string(), text.len(), now_unix).await;
            Ok(text)
        }
        Err(e) => {
            emit_denied(
                sink,
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
pub async fn write_os_file<P: PolicyArgument>(
    target: &Path,
    contents: &[u8],
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<PathBuf, OsGateError> {
    // Layer 0 — size cap BEFORE any path work (cheap reject of an oversize write).
    if contents.len() > cfg.max_write_bytes {
        let reason = format!(
            "content {} bytes exceeds max_write_bytes {}",
            contents.len(),
            cfg.max_write_bytes
        );
        emit_write_denied(sink, &target.display().to_string(), &reason, now_unix).await;
        return Err(OsGateError::WriteTooLarge(reason));
    }

    // Layer 1 — write-allowlist (canonical parent under allowed_write_paths;
    // symlink-escape + traversal rejected; fail-closed).
    let resolved = match resolve_write_target(target, &cfg.allowed_write_paths) {
        Ok(p) => p,
        Err(e) => {
            emit_write_denied(
                sink,
                &target.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate.
    let action = Action::OsFileWrite {
        path: resolved.clone(),
    };
    match evaluate(&action, policy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_write_denied(sink, &resolved.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_write_denied(
                sink,
                &resolved.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — GOLD-LF-P1-01: durable intent BEFORE the effect. Everything
    // above this line only ever refused a write; from here on a write can
    // actually happen, so this is the last point at which the WAL can still
    // learn what we were about to do. Fail closed: if the intent cannot be
    // recorded we do not write, because the alternative is a file on disk that
    // no audit trail explains.
    let resolved_display = resolved.display().to_string();
    let id = crate::wal::events::next_intent_id(b"os-file-write", &resolved_display, now_unix);
    if !emit_write_intent(sink, &id, &resolved_display, contents, now_unix)
        .await
        .permits_effect()
    {
        let reason = "mandatory pre-write audit intent could not be recorded".to_string();
        emit_write_denied(sink, &resolved_display, &reason, now_unix).await;
        return Err(OsGateError::Denied(reason));
    }

    // Layer 4 — atomic write + audit. `existed` records whether we overwrote.
    let existed = resolved.exists();
    match write_file_atomic(&resolved, contents) {
        Ok(()) => {
            emit_write_result(sink, &id, "written", None, now_unix).await;
            emit_write(sink, &resolved_display, contents.len(), existed, now_unix).await;
            Ok(resolved)
        }
        Err(e) => {
            emit_write_result(sink, &id, "failed", Some(&e.to_string()), now_unix).await;
            emit_write_denied(
                sink,
                &resolved_display,
                &format!("write-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::WriteFailed(e.to_string()))
        }
    }
}

/// The complete gated LAUNCH (PC-01 app-launch slice): exec-allowlist (exact
/// canonical match against `allowed_exec_paths`) → autonomy gate (Strict deny /
/// Standard+Elevated confirm / Full allow) → spawn (no args, no shell, detached
/// stdio) → WAL audit (`0xAC OS_APP_LAUNCH` on success, `0xAD
/// OS_APP_LAUNCH_DENIED` on any refusal/failure). Returns the resolved program
/// path + the launched PID on success.
pub async fn launch_os_app<P: PolicyArgument>(
    program: &Path,
    cfg: &OsToolsConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<(PathBuf, u32), OsGateError> {
    // Layer 1 — exec-allowlist (exact canonical match; regular-file-only; fail-closed).
    let resolved = match resolve_exec_program(program, &cfg.allowed_exec_paths) {
        Ok(p) => p,
        Err(e) => {
            emit_launch_denied(
                sink,
                &program.display().to_string(),
                &e.to_string(),
                now_unix,
            )
            .await;
            return Err(e.into());
        }
    };

    // Layer 2 — autonomy gate (the program is already allowlist-validated).
    let action = Action::OsAppLaunch {
        program: resolved.clone(),
    };
    match evaluate(&action, policy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_launch_denied(sink, &resolved.display().to_string(), &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_launch_denied(
                sink,
                &resolved.display().to_string(),
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }

    // Layer 3 — GOLD-LF-P1-01: durable intent BEFORE the spawn. A process that
    // started while its success frame was still in flight used to leave no
    // record at all; the intent is what makes that window visible.
    let resolved_display = resolved.display().to_string();
    let id = crate::wal::events::next_intent_id(b"os-app-launch", &resolved_display, now_unix);
    if !emit_launch_intent(sink, &id, &resolved_display, now_unix)
        .await
        .permits_effect()
    {
        let reason = "mandatory pre-launch audit intent could not be recorded".to_string();
        emit_launch_denied(sink, &resolved_display, &reason, now_unix).await;
        return Err(OsGateError::Denied(reason));
    }

    // Layer 4 — spawn + audit.
    match launch_program(&resolved) {
        Ok(pid) => {
            emit_launch_result(sink, &id, "launched", Some(pid), None, now_unix).await;
            emit_launch(sink, &resolved_display, pid, now_unix).await;
            Ok((resolved, pid))
        }
        Err(e) => {
            emit_launch_result(sink, &id, "failed", None, Some(&e.to_string()), now_unix).await;
            emit_launch_denied(
                sink,
                &resolved_display,
                &format!("launch-failed: {e}"),
                now_unix,
            )
            .await;
            Err(OsGateError::LaunchFailed(e.to_string()))
        }
    }
}

/// Characters that act as a LINE TERMINATOR in a terminal — the AUTO-EXECUTE
/// precondition a pastejacking clipboard write needs. Beyond ASCII `\n`/`\r`
/// this includes NEL (U+0085), LINE SEPARATOR (U+2028), and PARAGRAPH SEPARATOR
/// (U+2029), which some terminals also honour and whose UTF-8 encodings contain
/// no 0x0A/0x0D byte (so a `bytes()`-level scan would miss them).
#[cfg(feature = "os-clipboard")]
fn is_clipboard_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}

/// PC-01 (clipboard slice) — the complete gated clipboard READ. Layers, in
/// order: (-1) runtime kill-switches (`clipboard.enabled` + `read_enabled`),
/// (2) autonomy gate (`OsClipboardRead`: Strict deny / Standard + Elevated
/// confirm ⇒ fail-closed here / Full allow), (1) open the backend (graceful on
/// headless), (0) size cap on the value read back. Every refusal AND the success
/// emit `0xBC`/`0xBD` carrying ONLY `{op, bytes|reason, ts_unix}` — the clipboard
/// CONTENT is never in any frame, log, or error. Returns the text on success.
#[cfg(feature = "os-clipboard")]
pub async fn read_os_clipboard<P: PolicyArgument>(
    cfg: &crate::config::ClipboardConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<String, OsGateError> {
    // Layer -1 — runtime kill-switches (master + read sub-toggle). Fail-closed,
    // and a disabled surface NEVER touches the clipboard backend.
    if !cfg.enabled {
        let reason = "clipboard disabled (freedom.yaml::tools.os.clipboard.enabled=false)";
        emit_clipboard_denied(sink, "read", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    if !cfg.read_enabled {
        let reason =
            "clipboard read disabled (freedom.yaml::tools.os.clipboard.read_enabled=false)";
        emit_clipboard_denied(sink, "read", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    // Layer 2 — autonomy gate, BEFORE touching the backend: a denied read must
    // never open the clipboard.
    match evaluate(&Action::OsClipboardRead, policy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_clipboard_denied(sink, "read", &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_clipboard_denied(
                sink,
                "read",
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }
    // Layer 1 — open the backend + read. Graceful on headless / no-display. The
    // value is held in a `Zeroizing` buffer so a clipboard SECRET that the size
    // cap (or any error below) then rejects is WIPED from the heap on drop rather
    // than lingering in freed memory.
    let text = match crate::os_tools::clipboard::read_clipboard_text() {
        Ok(t) => zeroize::Zeroizing::new(t),
        Err(e) => {
            emit_clipboard_denied(sink, "read", "clipboard-backend-unavailable", now_unix).await;
            return Err(OsGateError::ClipboardUnavailable(e.to_string()));
        }
    };
    // Layer 0 (post-read) — size cap: never surface an oversize clipboard value.
    // The WAL reason is a STATIC tag; the byte-count detail lives only in the
    // returned error, never in the audit frame. (`text` wipes on the early drop.)
    if text.len() > cfg.max_clipboard_read_bytes {
        emit_clipboard_denied(sink, "read", "read-too-large", now_unix).await;
        return Err(OsGateError::ReadTooLarge(format!(
            "clipboard content {} bytes exceeds max_clipboard_read_bytes {}",
            text.len(),
            cfg.max_clipboard_read_bytes
        )));
    }
    // Layer 3 — audit (byte COUNT only — content never in the frame) + return.
    // The returned copy is the operator's (they invoked the read); the backend
    // buffer (`text`) wipes on drop at the end of this function.
    emit_clipboard_access(sink, "read", text.len(), now_unix).await;
    Ok(text.to_string())
}

/// PC-01 (clipboard slice) — the complete gated clipboard WRITE. Layers: (-1)
/// kill-switches (`enabled` + `write_enabled`), (0) size cap, (0b) pastejacking
/// newline guard (STRUCTURAL — fires at EVERY autonomy level, even Full, unless
/// `allow_newlines_in_write`), (2) autonomy gate (`OsClipboardWrite`: Strict +
/// Standard deny / Elevated confirm ⇒ fail-closed / Full allow), (1+3) write +
/// audit. `0xBC`/`0xBD` carry only `{op, bytes|reason, ts_unix}` — never content.
/// Returns the byte count written on success.
#[cfg(feature = "os-clipboard")]
pub async fn write_os_clipboard<P: PolicyArgument>(
    content: &str,
    cfg: &crate::config::ClipboardConfig,
    policy: P,
    sink: AuditSink<'_>,
    now_unix: i64,
) -> Result<usize, OsGateError> {
    // Layer -1 — kill-switches.
    if !cfg.enabled {
        let reason = "clipboard disabled (freedom.yaml::tools.os.clipboard.enabled=false)";
        emit_clipboard_denied(sink, "write", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    if !cfg.write_enabled {
        let reason =
            "clipboard write disabled (freedom.yaml::tools.os.clipboard.write_enabled=false)";
        emit_clipboard_denied(sink, "write", reason, now_unix).await;
        return Err(OsGateError::Denied(reason.into()));
    }
    // Layer 0 — size cap (cheap reject before anything else). STATIC WAL reason;
    // the byte-count detail lives only in the returned error, never the frame.
    if content.len() > cfg.max_clipboard_write_bytes {
        emit_clipboard_denied(sink, "write", "write-too-large", now_unix).await;
        return Err(OsGateError::WriteTooLarge(format!(
            "content {} bytes exceeds max_clipboard_write_bytes {}",
            content.len(),
            cfg.max_clipboard_write_bytes
        )));
    }
    // Layer 0a — control-character guard. ALWAYS rejected (independent of
    // autonomy AND of `allow_newlines_in_write`): ESC + the other C0/C1 control
    // characters have no legitimate place in clipboard TEXT and are the building
    // blocks of terminal-escape / bracketed-paste-escape injections (e.g.
    // `\x1b[201~…` closes paste mode so the trailing bytes auto-execute) that
    // would otherwise sail straight past the line-terminator guard. Tab is the
    // sole permitted control character; line terminators are handled in Layer 0b.
    if let Some(c) = content
        .chars()
        .find(|&c| c.is_control() && c != '\t' && !is_clipboard_line_terminator(c))
    {
        emit_clipboard_denied(sink, "write", "control-character-in-write", now_unix).await;
        return Err(OsGateError::PastejackingPattern(format!(
            "control character U+{:04X} not permitted in a clipboard write \
             (terminal-escape / paste-injection guard)",
            c as u32
        )));
    }
    // Layer 0b — pastejacking LINE-TERMINATOR guard. A line terminator is the
    // terminal AUTO-EXECUTE precondition. This covers not only `\n`/`\r` but the
    // Unicode line terminators NEL (U+0085), LS (U+2028), PS (U+2029) that some
    // terminals also act on and whose UTF-8 encodings contain no 0x0A/0x0D byte
    // (so a `bytes()`-only check would miss them). Rejected STRUCTURALLY at every
    // autonomy level (audited) unless the operator opts in.
    let has_line_terminator = content.chars().any(is_clipboard_line_terminator);
    if has_line_terminator && !cfg.allow_newlines_in_write {
        emit_clipboard_denied(sink, "write", "line-terminator-in-write", now_unix).await;
        return Err(OsGateError::PastejackingPattern(
            "content contains a line terminator (\\n / \\r / NEL / U+2028 / U+2029 — the terminal \
             auto-execute precondition); set tools.os.clipboard.allow_newlines_in_write=true to \
             permit multi-line writes"
                .into(),
        ));
    }
    // Layer 2 — autonomy gate.
    match evaluate(&Action::OsClipboardWrite, policy) {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            emit_clipboard_denied(sink, "write", &reason, now_unix).await;
            return Err(OsGateError::Denied(reason));
        }
        Decision::Confirm(reason) => {
            emit_clipboard_denied(
                sink,
                "write",
                &format!("confirm-required: {reason}"),
                now_unix,
            )
            .await;
            return Err(OsGateError::ConfirmRequired(reason));
        }
    }
    // Observability (Lens 3 advisory): a permitted multi-line write still carries
    // pastejacking risk; surface it for the operator's audit trail.
    if has_line_terminator {
        tracing::warn!(
            "OS clipboard write contains a line terminator (allow_newlines_in_write=true) — \
             pastejacking risk acknowledged by config"
        );
    }
    // Layer 1+3 — open the backend (graceful), write, audit (byte count only).
    match crate::os_tools::clipboard::write_clipboard_text(content) {
        Ok(()) => {
            emit_clipboard_access(sink, "write", content.len(), now_unix).await;
            Ok(content.len())
        }
        Err(e) => {
            emit_clipboard_denied(sink, "write", "clipboard-backend-unavailable", now_unix).await;
            Err(OsGateError::ClipboardUnavailable(e.to_string()))
        }
    }
}

async fn emit_launch(sink: AuditSink<'_>, program: &str, pid: u32, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "program": program,
        "pid": pid,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_APP_LAUNCH, payload).await;
}

async fn emit_launch_denied(sink: AuditSink<'_>, program: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "program": program,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_APP_LAUNCH_DENIED, payload).await;
}

/// GOLD-LF-P1-01. What happened to a mandatory intent frame.
///
/// The three-way split exists because "the frame did not land" has two
/// materially different causes, and collapsing them would either break working
/// installations or quietly weaken the guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentOutcome {
    /// The frame is durable in a WAL this process owns, or auditing is
    /// deliberately disabled (`AuditSink::None`). Safe to perform the effect.
    Recorded,
    /// The sink is the audit-RPC forward and no daemon was reachable.
    /// AUDIT-RPC-01 ratified that an unreachable forwarder must NOT fail the
    /// action, so this still permits the effect — but it is a real hole in the
    /// pre-mutation trail, not a success, and it is named as such.
    ForwardUnavailable,
    /// An authoritative sink rejected the append. The effect must not happen:
    /// this is the case where proceeding would leave a mutation that no audit
    /// trail explains.
    Failed,
}

impl IntentOutcome {
    /// AUDIT-RPC-01 keeps the best-effort forward permissive; only an
    /// authoritative sink failure blocks.
    fn permits_effect(self) -> bool {
        !matches!(self, IntentOutcome::Failed)
    }
}

/// GOLD-LF-P1-01. Like [`dispatch_frame`], but for an EXTENDED `(0x00,
/// subtype)` pair, and it *reports* what happened instead of swallowing the
/// error, so a caller can refuse a mutation whose intent could not be recorded.
async fn dispatch_extended_frame(
    sink: AuditSink<'_>,
    subtype: crate::wal::events::ExtendedSubtype,
    payload: Vec<u8>,
) -> IntentOutcome {
    let code = subtype as u8;
    match sink {
        AuditSink::None => IntentOutcome::Recorded,
        AuditSink::Writer(w) => {
            let header = crate::wal::HeaderBuilder::new(0x00, &payload)
                .event_subtype(code)
                .build();
            match w.append(header, payload).await {
                Ok(_) => IntentOutcome::Recorded,
                Err(_) => IntentOutcome::Failed,
            }
        }
        AuditSink::TrackedWriter { writer, status } => {
            let header = crate::wal::HeaderBuilder::new(0x00, &payload)
                .event_subtype(code)
                .build();
            match writer.append(header, payload).await {
                Ok(_) => IntentOutcome::Recorded,
                Err(error) => {
                    status.record(&error);
                    IntentOutcome::Failed
                }
            }
        }
        AuditSink::DaemonRpc(home) => {
            match crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
                home, 0x00, code, &payload,
            )
            .await
            {
                Ok(()) => IntentOutcome::Recorded,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        subtype = code,
                        "pre-mutation audit intent could not be forwarded; \
                         effect proceeds unaudited per AUDIT-RPC-01"
                    );
                    IntentOutcome::ForwardUnavailable
                }
            }
        }
        AuditSink::TrackedDaemonRpc { home, status } => {
            match crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
                home, 0x00, code, &payload,
            )
            .await
            {
                Ok(()) => IntentOutcome::Recorded,
                Err(error) => {
                    status.record_message(error.to_string());
                    IntentOutcome::ForwardUnavailable
                }
            }
        }
    }
}

/// GOLD-LF-P1-01 — durable record of a write we are *about* to perform. The
/// contents never enter the WAL; they are bound by digest so the result frame
/// (and a later forensic read of the file) can be tied to this exact intent.
async fn emit_write_intent(
    sink: AuditSink<'_>,
    intent_id: &str,
    path: &str,
    contents: &[u8],
    ts_unix: i64,
) -> IntentOutcome {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "path": path,
        "bytes": contents.len(),
        "contents_sha256": crate::wal::events::effect_digest(b"os-file-write", contents),
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsFileWriteIntent,
        payload,
    )
    .await
}

/// GOLD-LF-P1-01 — terminal outcome for one [`emit_write_intent`]. An intent
/// with no matching result is exactly the crash window this pair exists to
/// make visible.
async fn emit_write_result(
    sink: AuditSink<'_>,
    intent_id: &str,
    outcome: &str,
    detail: Option<&str>,
    ts_unix: i64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "detail": detail,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let _ = dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsFileWriteResult,
        payload,
    )
    .await;
}

/// GOLD-LF-P1-01 — durable record of a launch we are *about* to perform.
async fn emit_launch_intent(
    sink: AuditSink<'_>,
    intent_id: &str,
    program: &str,
    ts_unix: i64,
) -> IntentOutcome {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "program": program,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsAppLaunchIntent,
        payload,
    )
    .await
}

/// GOLD-LF-P1-01 — terminal outcome for one [`emit_launch_intent`], carrying
/// the PID so a forensic reader can tie the intent to a real process.
async fn emit_launch_result(
    sink: AuditSink<'_>,
    intent_id: &str,
    outcome: &str,
    pid: Option<u32>,
    detail: Option<&str>,
    ts_unix: i64,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent_id": intent_id,
        "outcome": outcome,
        "pid": pid,
        "detail": detail,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let _ = dispatch_extended_frame(
        sink,
        crate::wal::events::ExtendedSubtype::OsAppLaunchResult,
        payload,
    )
    .await;
}

async fn emit_write(sink: AuditSink<'_>, path: &str, bytes: usize, existed: bool, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "existed": existed,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_WRITE, payload).await;
}

async fn emit_write_denied(sink: AuditSink<'_>, path: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_WRITE_DENIED, payload).await;
}

async fn emit_read(sink: AuditSink<'_>, path: &str, bytes: usize, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "bytes": bytes,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_READ, payload).await;
}

async fn emit_denied(sink: AuditSink<'_>, path: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "path": path,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(sink, EVENT_TYPE_OS_FILE_DENIED, payload).await;
}

/// PC-01 clipboard — success audit (`0xBC`). **CONTENT IS NEVER A PARAMETER** —
/// only the operation (`read`/`write`) + the byte COUNT. This is the load-bearing
/// no-exfil invariant: a clipboard frequently holds a just-copied secret, so the
/// frame must carry metadata only.
#[cfg(feature = "os-clipboard")]
async fn emit_clipboard_access(sink: AuditSink<'_>, op: &str, bytes: usize, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "op": op,
        "bytes": bytes,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(
        sink,
        crate::wal::events::EVENT_TYPE_OS_CLIPBOARD_ACCESS,
        payload,
    )
    .await;
}

/// PC-01 clipboard — denial audit (`0xBD`). `reason` is a policy/diagnostic
/// string (+ byte counts) — NEVER the clipboard content.
#[cfg(feature = "os-clipboard")]
async fn emit_clipboard_denied(sink: AuditSink<'_>, op: &str, reason: &str, ts_unix: i64) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "op": op,
        "reason": reason,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    dispatch_frame(
        sink,
        crate::wal::events::EVENT_TYPE_OS_CLIPBOARD_DENIED,
        payload,
    )
    .await;
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
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        }
    }

    #[tokio::test]
    async fn write_allowlisted_file_at_elevated_then_read_back() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("out.txt");
        let cfg = cfg_for(dir.path());
        // Elevated ⇒ OsFileWrite is Allow.
        let resolved = write_os_file(
            &f,
            b"written",
            &cfg,
            AutonomyLevel::Elevated,
            AuditSink::None,
            0,
        )
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
            AuditSink::None,
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
            AuditSink::None,
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
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"y",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::None,
            0,
        )
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
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = write_os_file(
            &dir.path().join("x.txt"),
            b"way too long",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::None,
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
        let text = read_os_file(&f, &cfg, AutonomyLevel::Standard, AuditSink::None, 0)
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
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let r = read_os_file(&f, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn daemon_rpc_sink_without_listener_is_graceful_noop() {
        // AUDIT-RPC-01 Commit-2: when the sink is DaemonRpc but no daemon /
        // sidecar is reachable, the audit frame is silently dropped (best-effort)
        // — the gated read STILL succeeds. The action must never fail just
        // because audit forwarding is unavailable.
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"forwarded-or-not").unwrap();
        let cfg = cfg_for(dir.path());
        let home = tempdir().unwrap(); // no sidecar here ⇒ forward is Unavailable
        let text = read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::DaemonRpc(home.path()),
            0,
        )
        .await
        .expect("read must succeed even when audit-RPC forwarding is unavailable");
        assert_eq!(text, "forwarded-or-not");
    }

    #[tokio::test]
    async fn tracked_daemon_rpc_retains_exact_forward_failure() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        fs::write(&f, b"forwarded-or-not").unwrap();
        let cfg = cfg_for(dir.path());
        let home = tempdir().unwrap();
        let status = AuditStatus::default();

        let text = read_os_file(
            &f,
            &cfg,
            AutonomyLevel::Standard,
            AuditSink::TrackedDaemonRpc {
                home: home.path(),
                status: &status,
            },
            0,
        )
        .await
        .expect("domain action remains separate from the caller's required-audit policy");

        assert_eq!(text, "forwarded-or-not");
        assert!(
            status.failure().is_some(),
            "tracked daemon sink must retain the exact acknowledgement failure"
        );
    }

    #[tokio::test]
    async fn tracked_writer_retains_append_failure_for_required_caller() {
        let dir = tempdir().unwrap();
        let segment = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(segment).expect("spawn test writer");
        join.abort();
        let _ = join.await;
        let status = AuditStatus::default();

        dispatch_frame(
            AuditSink::TrackedWriter {
                writer: &writer,
                status: &status,
            },
            crate::wal::events::EVENT_TYPE_OS_APP_LAUNCH,
            br#"{"program":"test"}"#.to_vec(),
        )
        .await;

        assert!(
            status.failure().is_some(),
            "tracked sink must retain the append failure for the required-audit caller"
        );
    }

    #[tokio::test]
    async fn traversal_is_denied_even_at_full() {
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let evil = dir.path().join("..").join("etc").join("passwd");
        let r = read_os_file(&evil, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
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
        let r = read_os_file(&f, &cfg, AutonomyLevel::Strict, AuditSink::None, 0).await;
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
            AuditSink::Writer(&writer),
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
            allowed_exec_paths: Vec::new(),
            clipboard: crate::config::ClipboardConfig::default(),
        };
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let _ = read_os_file(&f, &cfg, AutonomyLevel::Full, AuditSink::Writer(&writer), 0).await;
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_FILE_DENIED);
    }

    // ── app-launch gate (PC-01 app-launch slice) ─────────────────────────────

    /// A real, argument-free, instantly-exiting system binary to allowlist.
    /// `None` on the rare host that lacks it (the dependent test then skips).
    fn real_arg_free_exe() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            for p in ["/bin/true", "/usr/bin/true"] {
                let pb = PathBuf::from(p);
                if pb.is_file() {
                    return Some(pb);
                }
            }
            None
        }
        #[cfg(windows)]
        {
            let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let pb = PathBuf::from(sys).join("System32").join("whoami.exe");
            if pb.is_file() { Some(pb) } else { None }
        }
    }

    fn exec_cfg(exe: &Path) -> OsToolsConfig {
        OsToolsConfig {
            allowed_paths: Vec::new(),
            max_read_bytes: 1024,
            allowed_write_paths: Vec::new(),
            max_write_bytes: 1024,
            allowed_exec_paths: vec![exe.to_path_buf()],
            clipboard: crate::config::ClipboardConfig::default(),
        }
    }

    #[tokio::test]
    async fn launch_deny_all_when_no_exec_allowlist() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // exec allowlist is empty here
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::DenyAll))
        ));
    }

    #[tokio::test]
    async fn launch_denied_at_strict() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Strict, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::Denied(_))));
    }

    #[tokio::test]
    async fn launch_confirms_at_standard_no_tty() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Standard, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn launch_confirms_at_elevated_stricter_than_write() {
        // Proves the exec gate is one notch stricter than OsFileWrite (which
        // Elevated ALLOWS): program execution still confirms at Elevated.
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let r = launch_os_app(&exe, &cfg, AutonomyLevel::Elevated, AuditSink::None, 0).await;
        assert!(matches!(r, Err(OsGateError::ConfirmRequired(_))));
    }

    #[tokio::test]
    async fn launch_succeeds_at_full_and_returns_pid() {
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let (resolved, pid) = launch_os_app(&exe, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
            .await
            .expect("full + allowlisted ⇒ launch");
        assert!(pid > 0);
        assert!(resolved.is_absolute());
    }

    #[tokio::test]
    async fn launch_non_allowlisted_binary_is_denied() {
        // A real, launchable binary that simply isn't the allowlisted one.
        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let other = dir.path().join("decoy");
        std::fs::write(&other, b"x").unwrap();
        let cfg = exec_cfg(&exe); // allowlists `exe`, not `other`
        let r = launch_os_app(&other, &cfg, AutonomyLevel::Full, AuditSink::None, 0).await;
        assert!(matches!(
            r,
            Err(OsGateError::Allowlist(AllowlistError::NotInAllowlist(_)))
        ));
    }

    #[tokio::test]
    async fn launch_emits_denied_frame_via_writer() {
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::spawn as wal_spawn;

        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // empty exec allowlist ⇒ deny-all
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let _ = launch_os_app(
            &exe,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            0,
        )
        .await;
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_OS_APP_LAUNCH_DENIED);
    }

    #[tokio::test]
    async fn launch_emits_success_frame_via_writer() {
        use crate::wal::spawn as wal_spawn;

        let Some(exe) = real_arg_free_exe() else {
            return;
        };
        let cfg = exec_cfg(&exe);
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        launch_os_app(
            &exe,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .expect("full launch");
        drop(writer);
        join.await.unwrap();

        // GOLD-LF-P1-01 moved the launch audit from "one frame" to an
        // intent/result pair around the spawn, so the success frame is no
        // longer first in the segment — locate it instead of assuming.
        let frames = decode_segment(&seg).await;
        let launch_at = frames
            .iter()
            .position(|(t, _, _)| *t == EVENT_TYPE_OS_APP_LAUNCH)
            .expect("the OS_APP_LAUNCH success frame must exist");
        assert!(frames[launch_at].2["pid"].as_u64().unwrap() > 0);

        let intent_at = frames
            .iter()
            .position(|(t, s, _)| {
                *t == 0x00 && *s == crate::wal::events::ExtendedSubtype::OsAppLaunchIntent as u8
            })
            .expect("a real spawn must be preceded by a durable intent");
        assert!(
            intent_at < launch_at,
            "the intent must be durable before the process starts"
        );
        assert_eq!(
            frames[intent_at].2["intent_id"],
            frames
                .iter()
                .find(|(t, s, _)| {
                    *t == 0x00 && *s == crate::wal::events::ExtendedSubtype::OsAppLaunchResult as u8
                })
                .expect("the intent must be paired by a result")
                .2["intent_id"]
        );
    }

    // ── PC-01 clipboard gate (feature `os-clipboard`) ────────────────────────
    #[cfg(feature = "os-clipboard")]
    mod clipboard_tests {
        use crate::config::ClipboardConfig;
        use crate::os_tools::gate::{
            AuditSink, OsGateError, read_os_clipboard, write_os_clipboard,
        };
        use crate::permissions::AutonomyLevel;
        // `emit_clipboard_access` is private to the gate module — reachable from
        // this descendant via `super::super::`.
        use super::super::emit_clipboard_access;

        fn clip_cfg(enabled: bool, read: bool, write: bool) -> ClipboardConfig {
            ClipboardConfig {
                enabled,
                read_enabled: read,
                write_enabled: write,
                max_clipboard_read_bytes: 4096,
                max_clipboard_write_bytes: 4096,
                allow_newlines_in_write: false,
            }
        }

        #[tokio::test]
        async fn master_switch_off_denies_both_even_at_full() {
            let cfg = clip_cfg(false, true, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_sub_toggle_off_denies() {
            let cfg = clip_cfg(true, false, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn write_sub_toggle_off_denies() {
            let cfg = clip_cfg(true, true, false);
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_denied_at_strict() {
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                read_os_clipboard(&cfg, AutonomyLevel::Strict, AuditSink::None, 0).await,
                Err(OsGateError::Denied(_))
            ));
        }

        #[tokio::test]
        async fn read_confirms_fail_closed_at_standard_and_elevated() {
            let cfg = clip_cfg(true, true, true);
            for lvl in [AutonomyLevel::Standard, AutonomyLevel::Elevated] {
                assert!(
                    matches!(
                        read_os_clipboard(&cfg, lvl, AuditSink::None, 0).await,
                        Err(OsGateError::ConfirmRequired(_))
                    ),
                    "read at {lvl:?} must fail closed (no TTY)"
                );
            }
        }

        #[tokio::test]
        async fn write_denied_at_strict_and_standard() {
            let cfg = clip_cfg(true, true, true);
            for lvl in [AutonomyLevel::Strict, AutonomyLevel::Standard] {
                assert!(
                    matches!(
                        write_os_clipboard("x", &cfg, lvl, AuditSink::None, 0).await,
                        Err(OsGateError::Denied(_))
                    ),
                    "write at {lvl:?} must Deny (stricter than app-launch)"
                );
            }
        }

        #[tokio::test]
        async fn write_confirms_fail_closed_at_elevated() {
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                write_os_clipboard("x", &cfg, AutonomyLevel::Elevated, AuditSink::None, 0).await,
                Err(OsGateError::ConfirmRequired(_))
            ));
        }

        #[tokio::test]
        async fn write_rejects_newline_structurally_even_at_full() {
            // Layer 0b fires BEFORE the autonomy gate + the backend.
            let cfg = clip_cfg(true, true, true);
            assert!(matches!(
                write_os_clipboard("rm -rf /\n", &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                    .await,
                Err(OsGateError::PastejackingPattern(_))
            ));
            assert!(
                matches!(
                    write_os_clipboard("a\rb", &cfg, AutonomyLevel::Full, AuditSink::None, 0).await,
                    Err(OsGateError::PastejackingPattern(_))
                ),
                "a carriage return is also an auto-execute precondition"
            );
        }

        #[tokio::test]
        async fn write_rejects_unicode_line_terminators() {
            // NEL (U+0085), LS (U+2028), PS (U+2029) — none contain 0x0A/0x0D, so a
            // bytes()-only guard would have missed them. All are auto-execute
            // preconditions and must be refused (allow_newlines off).
            let cfg = clip_cfg(true, true, true);
            for bad in ["a\u{0085}b", "a\u{2028}b", "a\u{2029}b"] {
                assert!(
                    matches!(
                        write_os_clipboard(bad, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                            .await,
                        Err(OsGateError::PastejackingPattern(_))
                    ),
                    "unicode line terminator in {bad:?} must be rejected"
                );
            }
        }

        #[tokio::test]
        async fn write_rejects_control_chars_even_when_newlines_allowed() {
            // ESC (bracketed-paste escape) + NUL + BEL are ALWAYS refused, even
            // with allow_newlines_in_write=true — controls bypass the line-terminator
            // guard and have no legitimate clipboard-text use.
            let mut cfg = clip_cfg(true, true, true);
            cfg.allow_newlines_in_write = true;
            for bad in ["benign\x1b[201~rm -rf /", "a\x00b", "ding\x07"] {
                assert!(
                    matches!(
                        write_os_clipboard(bad, &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                            .await,
                        Err(OsGateError::PastejackingPattern(_))
                    ),
                    "control char in {bad:?} must be rejected even with newlines allowed"
                );
            }
        }

        #[tokio::test]
        async fn write_allows_tab_through_the_guard() {
            // Tab is the sole permitted control character — it clears the guard +
            // autonomy and reaches the backend (Ok on a desktop, ClipboardUnavailable
            // on headless CI — both prove the guard did not reject it).
            let cfg = clip_cfg(true, true, true);
            let w = write_os_clipboard("col1\tcol2", &cfg, AutonomyLevel::Full, AuditSink::None, 0)
                .await;
            assert!(
                matches!(w, Ok(_) | Err(OsGateError::ClipboardUnavailable(_))),
                "a tab must pass the control-char guard (got {w:?})"
            );
        }

        #[tokio::test]
        async fn write_too_large_rejected_before_backend() {
            let mut cfg = clip_cfg(true, true, true);
            cfg.max_clipboard_write_bytes = 4;
            assert!(matches!(
                write_os_clipboard(
                    "way too long",
                    &cfg,
                    AutonomyLevel::Full,
                    AuditSink::None,
                    0
                )
                .await,
                Err(OsGateError::WriteTooLarge(_))
            ));
        }

        #[tokio::test]
        async fn newline_opted_in_passes_guard() {
            // With allow_newlines + Full + enabled, the gate clears the pastejack
            // guard + autonomy and reaches the backend. On a desktop the write
            // succeeds; on headless CI the backend is unavailable. BOTH outcomes
            // prove the guard did NOT reject it.
            let mut cfg = clip_cfg(true, true, true);
            cfg.allow_newlines_in_write = true;
            let w = write_os_clipboard(
                "line1\nline2",
                &cfg,
                AutonomyLevel::Full,
                AuditSink::None,
                0,
            )
            .await;
            assert!(
                matches!(w, Ok(_) | Err(OsGateError::ClipboardUnavailable(_))),
                "opted-in multi-line write must pass the pastejack guard (got {w:?})"
            );
        }

        /// The load-bearing no-exfil invariant: NO clipboard frame ever carries
        /// content. Drive a denied write (carrying a secret in the `content` arg)
        /// + a direct access emit through a real WAL writer, then assert no
        /// content-bearing key — and the literal secret — appears in any frame.
        #[tokio::test]
        async fn wal_frame_never_contains_content() {
            use crate::wal::events::{
                EVENT_TYPE_OS_CLIPBOARD_ACCESS, EVENT_TYPE_OS_CLIPBOARD_DENIED,
            };
            use crate::wal::frame::decode_frame;
            use crate::wal::segment_header::SEGMENT_HEADER_LEN;
            use crate::wal::spawn as wal_spawn;

            const SECRET: &str = "SUPER-SECRET-PASSWORD-hunter2";
            let segdir = tempfile::tempdir().unwrap();
            let seg = segdir.path().join("000001.wal");
            let (writer, join) = wal_spawn(seg.clone()).unwrap();
            // (1) Denied write (write_enabled=false) → 0xBD, secret in the arg.
            let _ = write_os_clipboard(
                SECRET,
                &clip_cfg(true, true, false),
                AutonomyLevel::Full,
                AuditSink::Writer(&writer),
                0,
            )
            .await;
            // (2) A FULL write of the secret that clears every gate + reaches the
            //     backend → emits either 0xBC access (byte count) on a desktop or
            //     0xBD "clipboard-backend-unavailable" on headless CI. Either way
            //     the SECRET must NOT appear in the frame.
            let _ = write_os_clipboard(
                SECRET,
                &clip_cfg(true, true, true),
                AutonomyLevel::Full,
                AuditSink::Writer(&writer),
                0,
            )
            .await;
            // (3) A direct success-path access emit (byte count only).
            emit_clipboard_access(AuditSink::Writer(&writer), "read", SECRET.len(), 0).await;
            drop(writer);
            join.await.unwrap();

            let bytes = tokio::fs::read(&seg).await.unwrap();
            let mut cursor = SEGMENT_HEADER_LEN;
            let mut clip_frames = 0;
            while cursor < bytes.len() {
                let Ok(frame) = decode_frame(&bytes[cursor..]) else {
                    break;
                };
                let et = frame.header.event_type;
                if et == EVENT_TYPE_OS_CLIPBOARD_ACCESS || et == EVENT_TYPE_OS_CLIPBOARD_DENIED {
                    let v: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    for forbidden in ["content", "text", "data", "preview", "value", "payload"] {
                        assert!(
                            v.get(forbidden).is_none(),
                            "clipboard frame leaked a content key '{forbidden}': {v}"
                        );
                    }
                    let raw = String::from_utf8_lossy(frame.payload);
                    assert!(
                        !raw.contains(SECRET),
                        "clipboard secret leaked into the WAL frame: {raw}"
                    );
                    clip_frames += 1;
                }
                cursor += frame.header.total_len as usize;
            }
            assert!(
                clip_frames >= 3,
                "expected >=3 clipboard frames, got {clip_frames}"
            );
        }
    }

    // ---- GOLD-LF-P1-01: INTENT/RESULT pre-mutation pairs -------------------

    /// Decode every frame in a finalized segment as
    /// `(event_type, event_subtype, payload_json)`.
    async fn decode_segment(seg: &std::path::Path) -> Vec<(u8, u8, serde_json::Value)> {
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;

        let bytes = tokio::fs::read(seg).await.unwrap();
        let mut out = Vec::new();
        let mut cursor = SEGMENT_HEADER_LEN;
        while cursor < bytes.len() {
            let Ok(frame) = decode_frame(&bytes[cursor..]) else {
                break;
            };
            let json = serde_json::from_slice(frame.payload).unwrap_or(serde_json::Value::Null);
            out.push((frame.header.event_type, frame.header.event_subtype, json));
            cursor += frame.header.total_len as usize;
        }
        out
    }

    #[tokio::test]
    async fn write_records_a_durable_intent_before_the_effect_and_pairs_the_result() {
        use crate::wal::events::ExtendedSubtype;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("audited.txt");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        let frames = decode_segment(&seg).await;
        let intent_at = frames
            .iter()
            .position(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsFileWriteIntent as u8)
            .expect("an OsFileWriteIntent frame must exist");
        let result_at = frames
            .iter()
            .position(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsFileWriteResult as u8)
            .expect("an OsFileWriteResult frame must exist");
        let effect_at = frames
            .iter()
            .position(|(t, _, _)| *t == EVENT_TYPE_OS_FILE_WRITE)
            .expect("the existing OS_FILE_WRITE frame must still be emitted");

        // The whole point of P1-01: the intent is durable BEFORE the effect.
        assert!(
            intent_at < result_at && intent_at < effect_at,
            "intent must precede both its result and the effect frame, got \
             intent={intent_at} result={result_at} effect={effect_at}"
        );
        assert_eq!(
            frames[intent_at].2["intent_id"], frames[result_at].2["intent_id"],
            "result must be paired to its intent by intent_id"
        );
        assert_eq!(frames[result_at].2["outcome"], "written");
        // Contents are hash-bound, never carried verbatim.
        assert_eq!(frames[intent_at].2["bytes"], 7);
        assert!(frames[intent_at].2.get("contents").is_none());
        assert_eq!(
            frames[intent_at].2["contents_sha256"],
            serde_json::Value::String(crate::wal::events::effect_digest(b"os-file-write", b"payload"))
        );
    }

    #[tokio::test]
    async fn write_is_refused_when_an_authoritative_sink_cannot_record_the_intent() {
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("must-not-exist.txt");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg).unwrap();
        // Kill the writer task so the handle is alive but every append fails.
        join.abort();
        let _ = join.await;

        let err = write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await
        .expect_err("a write whose mandatory intent cannot be recorded must be refused");

        assert!(
            matches!(err, OsGateError::Denied(ref m) if m.contains("pre-write audit intent")),
            "expected a pre-write-intent refusal, got {err:?}"
        );
        // Fail-closed means fail-closed: nothing may reach the disk.
        assert!(
            !target.exists(),
            "the file must not exist when its intent could not be recorded"
        );
    }

    #[tokio::test]
    async fn an_unreachable_audit_forward_still_permits_the_write() {
        // AUDIT-RPC-01 ratified that an unreachable forwarder must not fail the
        // action. P1-01 must not silently revoke that: the hole is reported as
        // `ForwardUnavailable`, not converted into a refusal.
        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path());
        let target = dir.path().join("forwarded.txt");
        let home = tempdir().unwrap(); // no sidecar ⇒ forward unavailable

        write_os_file(
            &target,
            b"payload",
            &cfg,
            AutonomyLevel::Full,
            AuditSink::DaemonRpc(home.path()),
            1_700_000_000,
        )
        .await
        .expect("an unreachable audit forward must not fail the write");
        assert!(target.exists());
    }

    #[test]
    fn intent_ids_differ_for_two_effects_on_one_path_in_the_same_second() {
        // Hashing (path, timestamp) alone would collide here — and repeated
        // writes to one path are exactly where a reader must tell the attempts
        // apart.
        let a = crate::wal::events::next_intent_id(b"os-file-write", "/tmp/same.txt", 1_700_000_000);
        let b = crate::wal::events::next_intent_id(b"os-file-write", "/tmp/same.txt", 1_700_000_000);
        assert_ne!(a, b, "intent ids must be unique per effect, not per second");
    }

    #[tokio::test]
    async fn a_refused_launch_leaves_no_orphan_intent() {
        // An intent means "an effect is about to happen". A launch refused at
        // the allowlist never reaches the spawn, so emitting an intent for it
        // would make every refusal look like an interrupted launch to a
        // forensic reader.
        use crate::wal::events::ExtendedSubtype;
        use crate::wal::spawn as wal_spawn;

        let dir = tempdir().unwrap();
        let cfg = cfg_for(dir.path()); // no allowed_exec_paths ⇒ refused
        let program = dir.path().join("nope.exe");

        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let outcome = launch_os_app(
            &program,
            &cfg,
            AutonomyLevel::Full,
            AuditSink::Writer(&writer),
            1_700_000_000,
        )
        .await;
        drop(writer);
        join.await.unwrap();
        assert!(outcome.is_err(), "an empty exec allowlist must refuse");

        let frames = decode_segment(&seg).await;
        assert!(
            !frames
                .iter()
                .any(|(t, s, _)| *t == 0x00 && *s == ExtendedSubtype::OsAppLaunchIntent as u8),
            "a refusal must not emit a pre-mutation intent"
        );
        assert!(
            frames
                .iter()
                .any(|(t, _, _)| *t == EVENT_TYPE_OS_APP_LAUNCH_DENIED),
            "the refusal itself must still be audited"
        );
    }
}
