//! GOLD-PROG-10 (OP-03) — Lightweight LSP subprocess client.
//!
//! Spawns an LSP server via stdio, sends `textDocument/didOpen`, and
//! collects `textDocument/publishDiagnostics` notifications — all over raw
//! JSON-RPC with `Content-Length` framing (identical to MCP transport).
//!
//! No `tower-lsp` or `lsp-types` crate required: we re-use the framing from
//! `mcp::transport::{frame, parse_frame}` and do minimal serde-typed parsing
//! of the notification we care about. All other server → client frames are
//! skipped silently.
//!
//! The subprocess I/O is fully synchronous (matching `cli::edit::run`'s sync
//! context). A single reader thread owns the `ChildStdout` and streams complete
//! frames over an `std::sync::mpsc` channel; the caller applies a deadline with
//! `recv_timeout`. `ChildStdout` has no `set_read_timeout`, and this
//! owned-reader design gives a timeout without ever aliasing the reader (a read
//! that outlives its deadline simply keeps the thread blocked; `Drop` kills the
//! child to close stdout, then joins the thread).

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;

use crate::lsp::types::{LspDiagnostic, severity_name};
use crate::mcp::transport::frame;

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// An active LSP server subprocess with open stdin/stdout pipes.
///
/// Dropped at end of scope: the child process receives SIGTERM / is left to
/// exit on its own once its stdin is closed (sufficient for short-lived
/// diagnostic sessions).
pub struct LspSession {
    child: Child,
    stdin: ChildStdin,
    /// Complete frames produced by the owned reader thread (which exclusively
    /// owns the `ChildStdout`). `Ok` = one frame body; `Err` = a read error.
    /// A closed channel (sender dropped) signals EOF.
    frame_rx: mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    /// Join handle for the reader thread — joined in `Drop` after `child.kill()`
    /// closes stdout, so the thread never outlives the session (no detach/leak).
    reader: Option<std::thread::JoinHandle<()>>,
    next_id: u64,
}

impl LspSession {
    /// Spawn `server_cmd` (first token) with the remaining tokens as args,
    /// send the JSON-RPC `initialize` request and `initialized` notification,
    /// and return a ready session.
    ///
    /// `workspace_root` is used as the `rootUri` for the `initialize` request.
    pub fn open(server_cmd: &str, workspace_root: &Path) -> Result<Self> {
        let mut parts = server_cmd.split_whitespace();
        let bin = parts
            .next()
            .context("lsp_server_cmd is empty")?;
        let rest: Vec<&str> = parts.collect();

        let mut child = Command::new(bin)
            .args(&rest)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // suppress server noise on our stderr
            .spawn()
            .with_context(|| format!("spawn LSP server {bin:?}"))?;

        let stdin = child.stdin.take().context("child has no stdin")?;
        let mut stdout = child.stdout.take().context("child has no stdout")?;

        // Spawn a reader thread that OWNS `stdout` and streams complete frames
        // over a channel. This removes the aliasing hazard of borrowing
        // `&mut self.stdout` into a per-read thread: a read timeout simply yields
        // no frame (the thread keeps owning stdout, blocked in `read`), and
        // `Drop` kills the child — closing stdout so the read returns EOF — then
        // joins the thread. No unsafe, no raw pointer, no detached thread.
        let (tx, frame_rx) = mpsc::channel::<std::result::Result<Vec<u8>, String>>();
        let reader = std::thread::spawn(move || {
            loop {
                match read_one_complete_frame(&mut stdout) {
                    Ok(Some(body)) => {
                        if tx.send(Ok(body)).is_err() {
                            break; // receiver gone — session dropped
                        }
                    }
                    Ok(None) => break, // clean EOF
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                        break;
                    }
                }
            }
            // `tx` dropped here → channel closes → `recv` sees Disconnected (EOF).
        });

        let mut sess = LspSession {
            child,
            stdin,
            frame_rx,
            reader: Some(reader),
            next_id: 1,
        };

        // `initialize` — required handshake before any other LSP method.
        let root_uri = path_to_uri(workspace_root);
        let init_params = json!({
            "processId": std::process::id(),
            "rootUri": root_uri,
            "capabilities": {
                "textDocument": {
                    "publishDiagnostics": { "relatedInformation": false }
                }
            },
            "initializationOptions": null
        });
        sess.send_request("initialize", init_params)?;
        // Read the `initialize` response (we do not inspect capabilities).
        sess.read_one_frame_timeout(Duration::from_millis(3_000))?;

        // `initialized` notification — no response expected.
        sess.send_notification("initialized", json!({}))?;

        Ok(sess)
    }

    /// Send `textDocument/didOpen` for `path` with `text` as the content.
    /// The language id is inferred from the file extension.
    pub fn notify_did_open(&mut self, path: &Path, text: &str) -> Result<()> {
        let uri = path_to_uri(path);
        let lang = language_id(path);
        self.send_notification(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": lang,
                    "version": 1,
                    "text": text
                }
            }),
        )
    }

    /// Read LSP server output for up to `timeout`, collecting any
    /// `textDocument/publishDiagnostics` notifications. Returns whatever was
    /// collected before the timeout or EOF; never errors on timeout/EOF alone.
    pub fn collect_diagnostics(&mut self, timeout: Duration) -> Result<Vec<LspDiagnostic>> {
        let mut diagnostics: Vec<LspDiagnostic> = Vec::new();
        let deadline = std::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match self.read_one_frame_timeout(remaining) {
                Ok(Some(body)) => {
                    if let Ok(parsed) = serde_json::from_slice::<RawNotification>(&body) {
                        if parsed.method.as_deref()
                            == Some("textDocument/publishDiagnostics")
                        {
                            if let Some(p) = parsed.params {
                                collect_from_params(p, &mut diagnostics);
                            }
                        }
                    }
                    // Non-matching frames: skip.
                }
                Ok(None) => break, // EOF
                Err(_) => break,   // timeout or read error
            }
        }

        Ok(diagnostics)
    }
}

impl Drop for LspSession {
    fn drop(&mut self) {
        // Kill the child FIRST: this closes its stdout, which unblocks the
        // reader thread's pending `read()` (it sees EOF) so the join below
        // always returns. `Child::kill()` is SIGKILL / TerminateProcess, so the
        // pipe is guaranteed to close even if the server ignores soft signals.
        let _ = self.child.kill();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

impl LspSession {
    fn send_request(&mut self, method: &str, params: serde_json::Value) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        self.write_msg(&msg)
    }

    fn send_notification(&mut self, method: &str, params: serde_json::Value) -> Result<()> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        self.write_msg(&msg)
    }

    fn write_msg(&mut self, msg: &serde_json::Value) -> Result<()> {
        let body = serde_json::to_vec(msg).context("serialize JSON-RPC message")?;
        let framed = frame(&body);
        self.stdin
            .write_all(&framed)
            .context("write JSON-RPC frame to LSP stdin")?;
        self.stdin.flush().context("flush LSP stdin")?;
        Ok(())
    }

    /// Pull the next complete frame from the reader thread, waiting at most
    /// `timeout`. `Ok(Some(body))` = a frame; `Ok(None)` = EOF (reader exited);
    /// `Err` = a timeout or a read error surfaced by the reader thread.
    ///
    /// No thread is spawned here and `ChildStdout` is never aliased: the reader
    /// thread spawned in `open()` owns it exclusively; we only read the channel.
    fn read_one_frame_timeout(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        match self.frame_rx.recv_timeout(timeout) {
            Ok(Ok(body)) => Ok(Some(body)),
            Ok(Err(e)) => Err(anyhow::anyhow!("LSP read error: {e}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(anyhow::anyhow!("LSP read timed out after {timeout:?}"))
            }
            // Sender dropped = the reader thread reached EOF or a fatal error
            // and exited. Treat as EOF; the error (if any) was delivered above.
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}

/// Blocking read of one complete Content-Length frame from `r`.
fn read_one_complete_frame<R: std::io::Read>(r: &mut R) -> Result<Option<Vec<u8>>> {

    // Read the header line-by-line until \r\n\r\n.
    let mut header_buf = Vec::with_capacity(64);
    loop {
        let mut byte = [0u8; 1];
        match r.read_exact(&mut byte) {
            Ok(()) => header_buf.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if header_buf.is_empty() {
                    return Ok(None); // clean EOF before any header
                }
                bail!("EOF mid-header after {} bytes", header_buf.len());
            }
            Err(e) => return Err(e.into()),
        }
        // Check for \r\n\r\n at the tail.
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 4096 {
            bail!("LSP header exceeds 4096 bytes — server sent garbage");
        }
    }

    // Parse Content-Length from header.
    let header_str = std::str::from_utf8(&header_buf).context("LSP header is not UTF-8")?;
    let content_length: usize = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("Content-Length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .context("LSP frame missing Content-Length")?;

    if content_length > 10 * 1024 * 1024 {
        bail!("LSP Content-Length {content_length} exceeds 10 MiB cap");
    }

    let mut body = vec![0u8; content_length];
    r.read_exact(&mut body).context("read LSP frame body")?;
    Ok(Some(body))
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON deserialization helpers (minimal, no lsp-types dependency)
// ──────────────────────────────────────────────────────────────────────────────

/// Minimal shape to detect the method field without deserializing the full body.
#[derive(Deserialize)]
struct RawNotification {
    method: Option<String>,
    params: Option<serde_json::Value>,
}

/// `textDocument/publishDiagnostics` params shape (LSP spec §3.17.1).
#[derive(Deserialize)]
struct PublishDiagnosticsParams {
    uri: String,
    diagnostics: Vec<RawDiagnostic>,
}

#[derive(Deserialize)]
struct RawDiagnostic {
    /// `{ line, character }` — both 0-based.
    range: DiagRange,
    /// 1=Error, 2=Warning, 3=Information, 4=Hint. Optional per spec.
    #[serde(default)]
    severity: Option<i64>,
    message: String,
}

#[derive(Deserialize)]
struct DiagRange {
    start: DiagPosition,
}

#[derive(Deserialize)]
struct DiagPosition {
    line: u32,
    character: u32,
}

fn collect_from_params(params: serde_json::Value, out: &mut Vec<LspDiagnostic>) {
    let Ok(p): std::result::Result<PublishDiagnosticsParams, _> =
        serde_json::from_value(params)
    else {
        return;
    };
    // Normalise the URI to a plain path for compact display.
    let file = uri_to_path(&p.uri);
    for d in p.diagnostics {
        out.push(LspDiagnostic {
            file: file.clone(),
            line: d.range.start.line,
            col: d.range.start.character,
            severity: d
                .severity
                .map(severity_name)
                .unwrap_or("warning")
                .to_string(),
            message: d.message,
        });
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// URI helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Convert a filesystem path to a `file://` URI as expected by LSP servers.
fn path_to_uri(p: &Path) -> String {
    // Canonicalize to absolute; fall back to the as-is path string.
    let abs = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let s = abs.to_string_lossy();
    // On Windows `canonicalize` returns `\\?\C:\...`; strip the UNC prefix.
    let s = s.trim_start_matches(r"\\?\");
    // Forward-slash the backslashes for URI.
    let s = s.replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

/// Strip the `file://` (or `file:///`) prefix and return a plain path string
/// for display. Falls back to the raw URI on unexpected shape.
fn uri_to_path(uri: &str) -> String {
    let stripped = uri
        .strip_prefix("file:///")
        .or_else(|| uri.strip_prefix("file://"))
        .unwrap_or(uri);
    // On Windows the result is `C:/...` — keep as-is (no backslash restore).
    stripped.to_string()
}

/// Infer the LSP `languageId` from a file extension.
fn language_id(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("ts") | Some("tsx") => "typescript",
        Some("js") | Some("jsx") => "javascript",
        Some("go") => "go",
        Some("c") | Some("h") => "c",
        Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") => "cpp",
        _ => "plaintext",
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_to_uri_unix_style() {
        let p = Path::new("/home/user/project/src/main.rs");
        let u = path_to_uri(p);
        // Must start with file:// and contain the path.
        assert!(u.starts_with("file://"), "got: {u}");
        assert!(u.contains("main.rs"), "got: {u}");
    }

    #[test]
    fn uri_to_path_strips_file_prefix() {
        assert_eq!(uri_to_path("file:///C:/foo/bar.rs"), "C:/foo/bar.rs");
        assert_eq!(uri_to_path("file:///home/user/main.rs"), "home/user/main.rs");
    }

    #[test]
    fn language_id_for_rust() {
        assert_eq!(language_id(Path::new("foo.rs")), "rust");
        assert_eq!(language_id(Path::new("bar.py")), "python");
        assert_eq!(language_id(Path::new("baz.txt")), "plaintext");
    }

    #[test]
    fn read_one_complete_frame_round_trips_content_length() {
        use crate::mcp::transport::frame;
        let body = br#"{"method":"test","params":{}}"#;
        let framed = frame(body);
        let mut cursor = std::io::Cursor::new(framed);
        let result = read_one_complete_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn read_one_complete_frame_eof_before_header_returns_none() {
        let mut cursor = std::io::Cursor::new(b"" as &[u8]);
        let result = read_one_complete_frame(&mut cursor).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn collect_from_params_parses_publish_diagnostics() {
        let params = serde_json::json!({
            "uri": "file:///src/main.rs",
            "diagnostics": [{
                "range": { "start": { "line": 5, "character": 2 }, "end": { "line": 5, "character": 10 } },
                "severity": 1,
                "message": "unused variable: `x`"
            }]
        });
        let mut out = Vec::new();
        collect_from_params(params, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].line, 5);
        assert_eq!(out[0].col, 2);
        assert_eq!(out[0].severity, "error");
        assert_eq!(out[0].message, "unused variable: `x`");
    }
}
