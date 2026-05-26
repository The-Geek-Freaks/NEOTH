//! Model Context Protocol (MCP) client — `~/.neoth/mcp_servers.yaml` config
//! + stdio JSON-RPC 2.0 client + `tools/list` + `tools/call`.
//!
//! ## What MCP gives NEOTH
//!
//! Operators run external MCP servers (Anthropic's, plus third-party
//! servers for Slack / GitHub / Postgres / filesystem / etc) and NEOTH
//! consumes their tool surface. Each configured server contributes one
//! or more `tools/list`-returned tool definitions; NEOTH's chat path can
//! call them via `tools/call`.
//!
//! ## Transport
//!
//! v0.1 ships **stdio** transport only — the most widely deployed MCP
//! transport. Operators configure `command + args + env`, NEOTH spawns
//! the child process, and JSON-RPC 2.0 frames flow over stdin/stdout
//! delimited by `Content-Length` headers per MCP spec.
//!
//! HTTP/SSE transport is a future addition once any real server NEOTH
//! cares about ships only over HTTP.
//!
//! ## Lifecycle
//!
//! 1. `McpClient::spawn(config)` starts the child + does the
//!    `initialize` handshake. Returns once the server responds with its
//!    capabilities.
//! 2. `client.list_tools()` returns the typed tool list.
//! 3. `client.call_tool(name, args)` invokes a tool, returns the
//!    structured result.
//! 4. Drop → child process is killed via the kill-on-drop handle.

pub mod catalogue;
pub mod client;
pub mod config;
pub mod codegraph_server;
pub mod dispatch_loop;
pub mod gate;
pub mod sanitizer;
pub mod tool_call_parser;
pub mod transport;

#[allow(unused_imports)]
pub use client::{McpClient, McpError, McpTool, ToolCallResult};
#[allow(unused_imports)]
pub use config::{AutorouteDecision, McpServerConfig, McpServers};
#[allow(unused_imports)]
pub use gate::{GateError, SanitizedTool, invoke_with_audit, list_tools_sanitized};
#[allow(unused_imports)]
pub use sanitizer::{
    SanitizerVerdict, sanitize_description, sanitize_schema_descriptions, sanitize_tool_name,
};
#[allow(unused_imports)]
pub use transport::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
