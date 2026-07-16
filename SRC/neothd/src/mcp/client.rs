//! MCP client — spawns an MCP server child process, does the
//! `initialize` handshake, and exposes `list_tools` + `call_tool`.
//!
//! Threading: the child process runs as a background tokio process,
//! and the client owns the stdin/stdout handles. Requests are sent
//! synchronously (write newline-delimited JSON, read one JSON response)
//! since v0.1 invokes one tool at a time per call site. Future
//! versions can layer a request/response multiplexer on top if
//! parallel tool calls become a hotspot.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::time::Instant;

use crate::mcp::config::McpServerConfig;
use crate::mcp::transport::{
    JsonRpcRequest, JsonRpcResponse, MAX_MCP_FRAME_BYTES, frame, parse_frame,
};

// Environment variables needed for ordinary process startup and the supported
// exact-pinned `npx` launcher. Everything else is absent unless the operator
// explicitly lists it in `mcp_servers.yaml::env` (including `from_env`). In
// particular, provider API keys and HTTP proxy variables are not ambient MCP
// authority.
const UNIX_CHILD_ENV_BASELINE: &[&str] = &[
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE",
];
const WINDOWS_CHILD_ENV_BASELINE: &[&str] = &[
    "PATH",
    "SystemRoot",
    "WINDIR",
    "SystemDrive",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

/// Default timeout for any single MCP request. 30s is generous for
/// `tools/list` (which servers cache) but tight enough to surface
/// hung servers quickly.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Latest MCP revision this client implements. The basic tools surface remains
/// compatible with the three preceding revisions.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    MCP_PROTOCOL_VERSION,
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// One tool definition as returned by `tools/list`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// JSON Schema describing the tool's input. Treated as opaque —
    /// callers thread it through to whichever LLM does the structured
    /// generation.
    #[serde(default, rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// MCP tool behaviour annotations (spec `tools/list` → `annotations`).
    /// The server's DECLARED EFFECT metadata — `readOnlyHint` /
    /// `destructiveHint` — used by ADOPT-22 SmartApprove to auto-approve a
    /// Confirm-gated call by its EFFECT, never by its name (the operator's
    /// trust-creep guard). `None` when the server declares no annotations.
    #[serde(default)]
    pub annotations: Option<ToolAnnotations>,
}

/// MCP tool behaviour annotations (spec: `ToolAnnotations`). Only the two hints
/// SmartApprove acts on are captured; unknown fields are ignored. Every hint is
/// `Option` because a server may declare some, all, or none.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct ToolAnnotations {
    /// The tool performs no environment mutation (read-only). The PRIMARY
    /// auto-approve signal.
    #[serde(default, rename = "readOnlyHint")]
    pub read_only_hint: Option<bool>,
    /// The tool may perform destructive (irreversible) updates. When `true`,
    /// SmartApprove NEVER auto-approves it regardless of any read-only hint.
    #[serde(default, rename = "destructiveHint")]
    pub destructive_hint: Option<bool>,
}

/// One content fragment returned by a `tools/call` invocation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum McpContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { data: String, mime_type: String },
    /// Catch-all so we can render unknown content types without losing
    /// the audit trail.
    #[serde(other)]
    Other,
}

/// Result of `tools/call`.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ToolCallResult {
    #[serde(default)]
    pub content: Vec<McpContent>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

/// Errors the client can surface.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("MCP server `{0}`: spawn failed: {1}")]
    Spawn(String, String),
    #[error("MCP server `{0}`: handshake failed: {1}")]
    Handshake(String, String),
    #[error("MCP server `{0}`: request timed out after {1:?}")]
    Timeout(String, Duration),
    #[error("MCP server `{0}`: protocol error: {1}")]
    Protocol(String, String),
    #[error("MCP server `{server}`: returned JSON-RPC error code {code}: {message}")]
    RpcError {
        server: String,
        code: i64,
        message: String,
    },
    #[error("MCP server `{0}`: stdin/stdout I/O error: {1}")]
    Io(String, String),
    #[error("MCP server `{0}`: incoming frame exceeds size limit")]
    FrameTooBig(String),
}

/// One live connection to an MCP server.
pub struct McpClient {
    server_id: String,
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Monotonic id allocator for outbound JSON-RPC requests.
    next_id: AtomicU64,
    /// Per-call timeout — applied via tokio::time::timeout.
    request_timeout: Duration,
    /// Whatever the server returned for `initialize.result`. Operators
    /// occasionally need the server's declared capabilities.
    pub server_info: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct InitializeParams<'a> {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'a str,
    capabilities: serde_json::Value,
    #[serde(rename = "clientInfo")]
    client_info: ClientInfo<'a>,
}

#[derive(Serialize)]
struct ClientInfo<'a> {
    name: &'a str,
    version: &'a str,
}

/// Build the complete child environment from a small startup baseline plus the
/// operator's resolved config. Windows environment names are case-insensitive,
/// so case aliases collapse to one key and ambiguous duplicate explicit keys
/// fail closed. The injected lookup keeps this pure enough to exercise Windows
/// semantics on every CI platform.
fn build_child_environment<F>(
    explicit: &HashMap<String, String>,
    windows: bool,
    mut ambient: F,
) -> std::result::Result<Vec<(OsString, OsString)>, String>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let normalize = |key: &str| {
        if windows {
            key.to_ascii_uppercase()
        } else {
            key.to_string()
        }
    };

    let mut explicit_by_key: BTreeMap<String, (String, OsString)> = BTreeMap::new();
    for (key, value) in explicit {
        let normalized = normalize(key);
        if let Some((existing, _)) = explicit_by_key.get(&normalized) {
            return Err(format!(
                "ambiguous MCP environment keys `{existing}` and `{key}` differ only by case"
            ));
        }
        explicit_by_key.insert(normalized, (key.clone(), OsString::from(value)));
    }

    let baseline = if windows {
        WINDOWS_CHILD_ENV_BASELINE
    } else {
        UNIX_CHILD_ENV_BASELINE
    };
    let mut merged: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for key in baseline {
        if let Some(value) = ambient(key) {
            merged.insert(normalize(key), (OsString::from(*key), value));
        }
    }
    // Explicit config always wins over a baseline key, including `Path` vs
    // `PATH` on Windows. No other ambient variable is ever inserted.
    for (normalized, (key, value)) in explicit_by_key {
        merged.insert(normalized, (OsString::from(key), value));
    }
    Ok(merged.into_values().collect())
}

/// Apply the MCP subprocess policy in one place so every spawn gets identical
/// environment, stdio, and drop semantics.
///
/// stderr is deliberately discarded instead of piped: server diagnostics may
/// contain secrets, and an undrained pipe can deadlock a verbose child. stdout
/// remains the bounded MCP protocol transport. `env_clear` is an authority
/// boundary, not a filesystem sandbox: the child still inherits the current
/// directory and the NEOTH user's ordinary filesystem permissions.
fn configure_child_process(cmd: &mut tokio::process::Command, child_env: &[(OsString, OsString)]) {
    cmd.env_clear();
    for (key, value) in child_env {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
}

impl McpClient {
    /// Spawn the configured MCP server + complete the `initialize`
    /// handshake. Returns once the server has acknowledged.
    pub async fn spawn(config: &McpServerConfig) -> Result<Self, McpError> {
        Self::spawn_with_timeout(config, DEFAULT_REQUEST_TIMEOUT).await
    }

    /// Like `spawn` but threads a custom request timeout — tests use
    /// 1s while production sticks with the 30s default.
    pub async fn spawn_with_timeout(
        config: &McpServerConfig,
        request_timeout: Duration,
    ) -> Result<Self, McpError> {
        // Every production MCP caller converges here. Validate before env
        // resolution or process creation so unpinned runtime fetches and
        // opaque wrappers fail closed uniformly. Ambient Node/npm overrides
        // are scrubbed below; explicitly configured overrides are rejected by
        // validate_launcher().
        config
            .validate_launcher()
            .map_err(|e| McpError::Spawn(config.id.clone(), e.to_string()))?;
        let env = config
            .resolve_env()
            .map_err(|e| McpError::Spawn(config.id.clone(), e.to_string()))?;
        let child_env = build_child_environment(&env, cfg!(windows), |key| std::env::var_os(key))
            .map_err(|e| McpError::Spawn(config.id.clone(), e))?;
        let mut cmd = tokio::process::Command::new(&config.command);
        cmd.args(&config.args);
        configure_child_process(&mut cmd, &child_env);
        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::Spawn(config.id.clone(), e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::Spawn(config.id.clone(), "no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::Spawn(config.id.clone(), "no stdout".into()))?;

        let mut client = Self {
            server_id: config.id.clone(),
            child,
            stdin,
            stdout,
            next_id: AtomicU64::new(1),
            request_timeout,
            server_info: None,
        };
        client.handshake().await?;
        Ok(client)
    }

    async fn handshake(&mut self) -> Result<(), McpError> {
        let params = InitializeParams {
            protocol_version: MCP_PROTOCOL_VERSION,
            capabilities: serde_json::json!({}),
            client_info: ClientInfo {
                name: "neoth",
                version: env!("CARGO_PKG_VERSION"),
            },
        };
        let resp = self.request("initialize", params).await?;
        let negotiated = resp
            .get("protocolVersion")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                McpError::Protocol(
                    self.server_id.clone(),
                    "initialize result omitted protocolVersion".into(),
                )
            })?;
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&negotiated) {
            return Err(McpError::Protocol(
                self.server_id.clone(),
                format!(
                    "server negotiated unsupported protocol version `{negotiated}` (supported: {})",
                    SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                ),
            ));
        }
        self.server_info = Some(resp);
        // Required lifecycle transition: the server must receive this before
        // normal tool requests begin.
        self.notify("notifications/initialized", serde_json::json!({}))
            .await?;
        Ok(())
    }

    async fn notify<P: Serialize>(&mut self, method: &str, params: P) -> Result<(), McpError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .map_err(|e| McpError::Protocol(self.server_id.clone(), e.to_string()))?;
        let message = frame(&body);
        let timeout = self.request_timeout;
        tokio::time::timeout(timeout, self.stdin.write_all(&message))
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;
        tokio::time::timeout(timeout, self.stdin.flush())
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;
        Ok(())
    }

    /// Send a request + await the matching response. Increments `next_id`
    /// so each call has a unique JSON-RPC id; in a single-threaded request
    /// pattern that's all we need.
    async fn request<P: Serialize>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<serde_json::Value, McpError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest::new(id, method, params);
        let body = serde_json::to_vec(&req)
            .map_err(|e| McpError::Protocol(self.server_id.clone(), e.to_string()))?;
        let framed = frame(&body);
        let timeout = self.request_timeout;
        // One absolute deadline for the whole request (write + read). A
        // per-read timeout would reset on every frame, so a server that
        // dribbles notification frames forever could pin the caller
        // indefinitely; `timeout_at` bounds the total wall-clock instead.
        let deadline = Instant::now() + timeout;

        // Write request — bounded by the deadline so a stuck server cannot
        // hold the calling task forever.
        tokio::time::timeout_at(deadline, self.stdin.write_all(&framed))
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;
        tokio::time::timeout_at(deadline, self.stdin.flush())
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;

        // Read newline-delimited responses until we see the one whose id matches our
        // request. Notifications (no id) and responses for other in-flight
        // ids are drained and skipped rather than killing the connection
        // (COR-26: a server legitimately interleaves notifications/* frames
        // while we wait). The inner loop drains every complete frame already
        // in the buffer before blocking on another read, since multiple
        // frames can arrive in a single read and our match may already be
        // buffered — a plain `continue` to the read would then hang.
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            loop {
                let (body, consumed) = match parse_frame(&buf) {
                    Ok(None) => break,
                    Ok(Some(frame)) => frame,
                    Err(e) => {
                        return Err(McpError::Protocol(self.server_id.clone(), e.to_string()));
                    }
                };
                match classify_frame(&body, id, &self.server_id)? {
                    FrameMatch::Response(resp) => {
                        if let Some(err) = resp.error {
                            return Err(McpError::RpcError {
                                server: self.server_id.clone(),
                                code: err.code,
                                message: err.message,
                            });
                        }
                        return Ok(resp.result.unwrap_or(serde_json::Value::Null));
                    }
                    FrameMatch::Skip => {
                        buf.drain(..consumed);
                    }
                }
            }

            let read_result = tokio::time::timeout_at(deadline, self.stdout.read(&mut chunk)).await;
            let n = match read_result {
                Ok(Ok(0)) => {
                    return Err(McpError::Io(
                        self.server_id.clone(),
                        "server closed stdout".into(),
                    ));
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    return Err(McpError::Io(self.server_id.clone(), e.to_string()));
                }
                Err(_) => return Err(McpError::Timeout(self.server_id.clone(), timeout)),
            };
            buf.extend_from_slice(&chunk[..n]);
            if !buf.contains(&b'\n') && buf.len() > MAX_MCP_FRAME_BYTES {
                return Err(McpError::FrameTooBig(self.server_id.clone()));
            }
        }
    }

    /// Fetch the server's tool catalogue. Returns the typed list so the
    /// caller can render it or thread it into an LLM tool-call request.
    pub async fn list_tools(&mut self) -> Result<Vec<McpTool>, McpError> {
        let result = self.request("tools/list", serde_json::json!({})).await?;
        let tools = result
            .get("tools")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let parsed: Vec<McpTool> = serde_json::from_value(tools)
            .map_err(|e| McpError::Protocol(self.server_id.clone(), e.to_string()))?;
        Ok(parsed)
    }

    /// Invoke a tool by name. `arguments` is the JSON object passed
    /// straight through to the server.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolCallResult, McpError> {
        let result = self
            .request(
                "tools/call",
                serde_json::json!({
                    "name": name,
                    "arguments": arguments,
                }),
            )
            .await?;
        let parsed: ToolCallResult = serde_json::from_value(result)
            .map_err(|e| McpError::Protocol(self.server_id.clone(), e.to_string()))?;
        Ok(parsed)
    }

    /// Server identifier (from the config). Useful for log spans.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // `kill_on_drop(true)` already takes care of the child but be
        // defensive — if for some reason the child is still alive on
        // drop, ensure it dies. start_kill is best-effort.
        let _ = self.child.start_kill();
    }
}

/// Outcome of inspecting one decoded JSON-RPC frame against the request id
/// we are currently awaiting.
enum FrameMatch {
    /// The frame is the response to our request — parsed and ready.
    Response(JsonRpcResponse),
    /// Not our response (a notification, or a response for another in-flight
    /// id) — the caller should drain it and keep reading.
    Skip,
}

/// Classify a decoded frame body relative to the awaited request `id`.
///
/// COR-26: the old read loop deserialized every frame straight into
/// `JsonRpcResponse` and `return`ed a hard `Protocol` error on any id
/// mismatch — so a single server notification (which a well-behaved MCP
/// server emits via `notifications/*`) tore down the whole connection.
/// Parse leniently into a `Value` first: a frame whose `id` does not match
/// ours — including a notification with no `id` at all — is `Skip`, not a
/// failure. Only a body that is not valid JSON-RPC is a genuine protocol
/// violation (`Err`).
fn classify_frame(body: &[u8], id: u64, server_id: &str) -> Result<FrameMatch, McpError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| McpError::Protocol(server_id.to_string(), e.to_string()))?;
    if value.get("id").and_then(serde_json::Value::as_u64) != Some(id) {
        return Ok(FrameMatch::Skip);
    }
    let resp: JsonRpcResponse = serde_json::from_value(value)
        .map_err(|e| McpError::Protocol(server_id.to_string(), e.to_string()))?;
    Ok(FrameMatch::Response(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::McpServerConfig;

    /// Subprocess fixture for the environment/stderr policy regression below.
    /// In an ordinary test run the marker is absent and this is a no-op. The
    /// parent test re-runs only this test in the current test executable with
    /// the marker explicitly injected into the scrubbed child environment.
    #[test]
    fn environment_probe_child() {
        if std::env::var("NEOTH_MCP_ENV_PROBE").as_deref() != Ok("neoth-fixture-v1") {
            return;
        }
        use std::io::Write as _;

        // Larger than ordinary OS pipe buffers. The parent completes because
        // the production policy sends MCP stderr to null instead of leaving an
        // unread pipe that can fill and deadlock.
        let chunk = [b'x'; 4096];
        let mut stderr = std::io::stderr().lock();
        for _ in 0..256 {
            stderr.write_all(&chunk).expect("write stderr fixture");
        }
        stderr.flush().expect("flush stderr fixture");

        let result_path = std::env::var("NEOTH_MCP_ENV_RESULT").expect("result path injected");
        let report = serde_json::json!({
            "ambient_api_key": std::env::var("OPENAI_API_KEY").ok(),
            "ambient_proxy": std::env::var("HTTPS_PROXY").ok(),
            "explicit_token": std::env::var("MCP_EXPLICIT_TOKEN").ok(),
        });
        std::fs::write(result_path, serde_json::to_vec(&report).unwrap())
            .expect("write environment report");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn child_scrubs_ambient_secrets_keeps_explicit_env_and_cannot_stderr_deadlock() {
        let _env = crate::test_env::lock();
        let old_api_key = std::env::var_os("OPENAI_API_KEY");
        let old_proxy = std::env::var_os("HTTPS_PROXY");
        unsafe {
            std::env::set_var("OPENAI_API_KEY", "ambient-api-key-must-not-leak");
            std::env::set_var("HTTPS_PROXY", "http://ambient-proxy.invalid");
        }

        let dir = tempfile::tempdir().unwrap();
        let result_path = dir.path().join("environment.json");
        let mut explicit = HashMap::new();
        explicit.insert("NEOTH_MCP_ENV_PROBE".into(), "neoth-fixture-v1".into());
        explicit.insert(
            "NEOTH_MCP_ENV_RESULT".into(),
            result_path.to_string_lossy().into_owned(),
        );
        explicit.insert("MCP_EXPLICIT_TOKEN".into(), "configured-token".into());
        let child_env =
            build_child_environment(&explicit, cfg!(windows), |key| std::env::var_os(key)).unwrap();

        let mut cmd = tokio::process::Command::new(std::env::current_exe().unwrap());
        cmd.arg("environment_probe_child").arg("--nocapture");
        configure_child_process(&mut cmd, &child_env);
        // stdout is irrelevant to this fixture; production keeps it piped for
        // MCP frames, but overriding it here avoids retaining libtest chatter.
        cmd.stdout(Stdio::null());
        let run: anyhow::Result<std::process::ExitStatus> = async {
            let mut child = cmd.spawn()?;
            Ok(tokio::time::timeout(Duration::from_secs(10), child.wait()).await??)
        }
        .await;

        match old_api_key {
            Some(value) => unsafe { std::env::set_var("OPENAI_API_KEY", value) },
            None => unsafe { std::env::remove_var("OPENAI_API_KEY") },
        }
        match old_proxy {
            Some(value) => unsafe { std::env::set_var("HTTPS_PROXY", value) },
            None => unsafe { std::env::remove_var("HTTPS_PROXY") },
        }

        let status = run.expect("environment probe child must start and finish");
        assert!(status.success(), "environment probe child failed: {status}");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap();
        assert_eq!(report["ambient_api_key"], serde_json::Value::Null);
        assert_eq!(report["ambient_proxy"], serde_json::Value::Null);
        assert_eq!(report["explicit_token"], "configured-token");
    }

    #[test]
    fn windows_environment_keys_are_case_insensitive_and_explicit_wins() {
        let mut explicit = HashMap::new();
        explicit.insert("Path".into(), "explicit-path".into());
        let merged = build_child_environment(&explicit, true, |key| {
            key.eq_ignore_ascii_case("PATH")
                .then(|| OsString::from("ambient-path"))
        })
        .unwrap();
        let paths: Vec<_> = merged
            .iter()
            .filter(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"))
            .collect();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].1, OsString::from("explicit-path"));

        explicit.insert("PATH".into(), "ambiguous-second-value".into());
        let error = build_child_environment(&explicit, true, |_| None).unwrap_err();
        assert!(error.contains("differ only by case"));
    }

    #[tokio::test]
    async fn spawn_reports_actionable_error_on_bad_command() {
        let cfg = McpServerConfig {
            id: "test".into(),
            description: None,
            command: "definitely-not-a-real-binary-xyz".into(),
            args: vec![],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: None,
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        };
        let result = McpClient::spawn_with_timeout(&cfg, Duration::from_millis(200)).await;
        let err = match result {
            Ok(_) => panic!("expected Err on bad command"),
            Err(e) => e,
        };
        match err {
            McpError::Spawn(id, _) => assert_eq!(id, "test"),
            other => panic!("expected Spawn error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spawn_rejects_unpinned_npx_before_process_creation() {
        let cfg = McpServerConfig {
            id: "unpinned".into(),
            description: None,
            command: "npx".into(),
            args: vec!["-y".into(), "example-mcp@latest".into()],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: Some(vec!["read".into()]),
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        };
        let error = match McpClient::spawn_with_timeout(&cfg, Duration::from_millis(200)).await {
            Ok(_) => panic!("unpinned launcher must fail before spawn"),
            Err(error) => error,
        };
        match error {
            McpError::Spawn(id, detail) => {
                assert_eq!(id, "unpinned");
                assert!(detail.contains("exact-version"));
            }
            other => panic!("expected Spawn error, got {other:?}"),
        }
    }

    #[test]
    fn mcp_tool_deserialises_minimal_shape() {
        let body = r#"{"name":"echo","description":"echo back","inputSchema":{"type":"object"}}"#;
        let t: McpTool = serde_json::from_str(body).unwrap();
        assert_eq!(t.name, "echo");
        assert_eq!(t.description.as_deref(), Some("echo back"));
    }

    #[test]
    fn tool_call_result_deserialises_text_content() {
        let body = r#"{
            "content": [{"type":"text","text":"hello"}],
            "isError": false
        }"#;
        let r: ToolCallResult = serde_json::from_str(body).unwrap();
        assert_eq!(r.content.len(), 1);
        assert!(matches!(r.content[0], McpContent::Text { ref text } if text == "hello"));
        assert!(!r.is_error);
    }

    #[test]
    fn tool_call_result_is_error_flag_round_trips() {
        let body = r#"{"content":[{"type":"text","text":"failed"}],"isError":true}"#;
        let r: ToolCallResult = serde_json::from_str(body).unwrap();
        assert!(r.is_error);
    }

    #[test]
    fn frame_too_big_error_variant_is_constructible() {
        // Smoke test: FrameTooBig is constructible and formats correctly.
        // The read-loop cap enforcement is exercised in request(); this test
        // verifies the error variant and its Display output are correctly wired.
        let e = McpError::FrameTooBig("my-server".into());
        let msg = format!("{e}");
        assert!(msg.contains("my-server"), "server id missing: {msg}");
        assert!(msg.contains("size limit"), "limit text missing: {msg}");
    }

    #[test]
    fn classify_frame_matches_our_id_and_skips_the_rest() {
        // COR-26: the frame whose id matches the awaited request is a Response;
        // a response for another id, or a notification with no id, is Skip
        // (not a connection-killing error); only invalid JSON-RPC is an Err.
        let ours = br#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#;
        assert!(matches!(
            classify_frame(ours, 7, "srv").unwrap(),
            FrameMatch::Response(_)
        ));

        let other_id = br#"{"jsonrpc":"2.0","id":99,"result":{}}"#;
        assert!(matches!(
            classify_frame(other_id, 7, "srv").unwrap(),
            FrameMatch::Skip
        ));

        // A real MCP notification carries a method and NO id.
        let notification =
            br#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#;
        assert!(matches!(
            classify_frame(notification, 7, "srv").unwrap(),
            FrameMatch::Skip
        ));

        // A matching-id frame carrying a JSON-RPC error is still our Response
        // (the caller maps the embedded error to RpcError).
        let err_resp = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"no"}}"#;
        assert!(matches!(
            classify_frame(err_resp, 7, "srv").unwrap(),
            FrameMatch::Response(_)
        ));

        // Garbage that isn't JSON at all is a genuine protocol violation.
        assert!(classify_frame(b"not json", 7, "srv").is_err());
    }
}
