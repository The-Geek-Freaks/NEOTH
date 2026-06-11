//! MCP client — spawns an MCP server child process, does the
//! `initialize` handshake, and exposes `list_tools` + `call_tool`.
//!
//! Threading: the child process runs as a background tokio process,
//! and the client owns the stdin/stdout handles. Requests are sent
//! synchronously (write framed JSON, read framed JSON response)
//! since v0.1 invokes one tool at a time per call site. Future
//! versions can layer a request/response multiplexer on top if
//! parallel tool calls become a hotspot.

use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout};

use crate::mcp::config::McpServerConfig;
use crate::mcp::transport::{JsonRpcRequest, JsonRpcResponse, frame, parse_frame};

/// Default timeout for any single MCP request. 30s is generous for
/// `tools/list` (which servers cache) but tight enough to surface
/// hung servers quickly.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
        let env = config
            .resolve_env()
            .map_err(|e| McpError::Spawn(config.id.clone(), e.to_string()))?;
        let mut cmd = tokio::process::Command::new(&config.command);
        cmd.args(&config.args)
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
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
            protocol_version: "2024-11-05",
            capabilities: serde_json::json!({}),
            client_info: ClientInfo {
                name: "neoth",
                version: env!("CARGO_PKG_VERSION"),
            },
        };
        let resp = self.request("initialize", params).await?;
        self.server_info = Some(resp);
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

        // Write request — bounded by timeout so a stuck server cannot
        // hold the calling task forever.
        tokio::time::timeout(timeout, self.stdin.write_all(&framed))
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;
        tokio::time::timeout(timeout, self.stdin.flush())
            .await
            .map_err(|_| McpError::Timeout(self.server_id.clone(), timeout))?
            .map_err(|e| McpError::Io(self.server_id.clone(), e.to_string()))?;

        // Read framed responses until we see the one whose id matches our
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

            let read_result = tokio::time::timeout(timeout, self.stdout.read(&mut chunk)).await;
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
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#;
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
