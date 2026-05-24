//! MCP tool catalogue assembly for chat-time system-prompt injection.
//!
//! Step 1 of "autonomous MCP routing": before the chat dispatcher hands a
//! prompt to the LLM, it asks each enabled MCP server for its
//! `tools/list`, sanitises the descriptions via [`super::gate::list_tools_sanitized`],
//! and renders one operator-readable block per server that the chat
//! loop prepends to the system prompt. The LLM now SEES which tools
//! exist and can refer to them by name.
//!
//! Step 2 — autonomous invocation — adds a parser that scans the LLM's
//! response text for a structured tool-call marker and dispatches it
//! via [`super::gate::invoke_with_audit`]. That ships separately so
//! Step 1 lands first without an LLM-format dependency.
//!
//! Failure modes (operator-friendly):
//!   - Server unreachable / handshake timeout → skip + log warning,
//!     other servers still surface their tools.
//!   - `tools/list` returns flagged descriptions → catalogue
//!     annotates with `[FLAGGED: <patterns>]` so the LLM sees the
//!     verdict before considering the tool.
//!   - No enabled servers → returns `None`; chat skips injection.

use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

use crate::mcp::client::McpClient;
use crate::mcp::config::McpServers;
use crate::mcp::gate::list_tools_sanitized;

/// Per-server spawn timeout. Chat hot-path can't afford to block 30s
/// waiting for a misconfigured server — 5s is generous for a healthy
/// MCP server's handshake while still keeping the prompt-build phase
/// fast on the unhappy path.
pub const CATALOGUE_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a system-prompt-ready block describing every enabled MCP
/// server's tool catalogue. Returns `None` when no enabled servers are
/// configured — the caller skips injection without noise.
///
/// Output shape (Markdown so the LLM treats it as structured text):
///
/// ````text
/// # Available MCP Tools
///
/// Tools you can invoke by emitting a fenced `mcp-tool-call` JSON block:
///
/// ```mcp-tool-call
/// {"server": "<id>", "tool": "<name>", "arguments": {...}}
/// ```
///
/// ## Server `filesystem`
/// - **read_file** — Read a file from the operator's filesystem.
///   Input schema: `{"path": "string"}`
/// - **list_directory** — ...
///
/// ## Server `github`
/// - **search_repos** — ...
/// ````
///
/// Server entries that fail to spawn are listed as
/// `## Server <id> — UNAVAILABLE: <reason>` so the operator + the LLM
/// see why the catalogue is short. Empty catalogues (server up but
/// `tools/list` returned no tools) are omitted entirely.
pub async fn assemble_catalogue(servers: &McpServers) -> Option<String> {
    let enabled = servers.enabled();
    if enabled.is_empty() {
        return None;
    }
    let mut blocks = Vec::with_capacity(enabled.len());
    for cfg in enabled {
        match build_server_block(cfg).await {
            Ok(Some(block)) => blocks.push(block),
            Ok(None) => {
                info!(server = %cfg.id, "MCP server returned empty tool catalogue, skipping");
            }
            Err(e) => {
                warn!(
                    server = %cfg.id,
                    error = %e,
                    "MCP server unreachable for catalogue assembly, surfacing as UNAVAILABLE",
                );
                blocks.push(format!("## Server `{}` — UNAVAILABLE: {}\n", cfg.id, e));
            }
        }
    }
    if blocks.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(512 + blocks.iter().map(|b| b.len()).sum::<usize>());
    out.push_str(CATALOGUE_HEADER);
    out.push('\n');
    for b in blocks {
        out.push_str(&b);
        out.push('\n');
    }
    Some(out)
}

/// The static preamble explaining how the LLM should invoke a tool.
/// Pinned here so future tool-call parsers know the exact format the
/// model was instructed to produce.
const CATALOGUE_HEADER: &str = "\
# Available MCP Tools

NEOTH exposes the tools below via the Model Context Protocol (MCP).
To call one, emit a fenced code block tagged `mcp-tool-call` containing
a JSON object with `server`, `tool`, and `arguments`. Example:

```mcp-tool-call
{\"server\": \"filesystem\", \"tool\": \"read_file\", \"arguments\": {\"path\": \"/tmp/x.txt\"}}
```

NEOTH executes the call, redacts secrets, audits via WAL, and threads
the result back as the next user message. You may chain multiple calls.
Only the tools listed below are reachable — calling anything else is
rejected before reaching the server.
";

async fn build_server_block(cfg: &crate::mcp::config::McpServerConfig) -> Result<Option<String>> {
    // Bound the per-server cost with a timeout so a stuck server can't
    // freeze the chat hot path. McpClient::spawn_with_timeout already
    // wires the same value through to handshake; we wrap the whole
    // (spawn + list) phase here for one shared budget.
    let work = async {
        let mut client = McpClient::spawn_with_timeout(cfg, CATALOGUE_SERVER_TIMEOUT).await?;
        let tools = list_tools_sanitized(&mut client).await?;
        Ok::<_, anyhow::Error>(tools)
    };
    let tools = match tokio::time::timeout(CATALOGUE_SERVER_TIMEOUT, work).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!("timed out after {:?}", CATALOGUE_SERVER_TIMEOUT),
    };
    if tools.is_empty() {
        return Ok(None);
    }

    // Honour the per-server allowlist: only surface tools the operator
    // pinned. Mirrors the gate's runtime enforcement so the LLM doesn't
    // get tempted by tools it can't actually call.
    let allow = cfg.allow_tools.as_ref();
    let mut entries = Vec::with_capacity(tools.len());
    for t in &tools {
        if let Some(list) = allow {
            if !list.iter().any(|name| name == &t.tool.name) {
                continue;
            }
        }
        entries.push(render_tool_entry(t));
    }
    if entries.is_empty() {
        return Ok(None);
    }
    let mut block = String::with_capacity(64 + entries.iter().map(|e| e.len()).sum::<usize>());
    block.push_str(&format!("## Server `{}`\n", cfg.id));
    if let Some(desc) = cfg.description.as_deref() {
        block.push_str(&format!("{desc}\n\n"));
    }
    for e in entries {
        block.push_str(&e);
    }
    Ok(Some(block))
}

fn render_tool_entry(t: &crate::mcp::gate::SanitizedTool) -> String {
    let name = &t.tool.name;
    let desc = t
        .tool
        .description
        .as_deref()
        .unwrap_or("(no description provided)");
    let schema = render_input_schema(&t.tool.input_schema);
    let flagged = if t.verdict.flagged {
        format!(" [FLAGGED: {}]", t.verdict.matched_patterns.join(", "))
    } else {
        String::new()
    };
    format!("- **{name}**{flagged} — {desc}\n  Input schema: `{schema}`\n")
}

/// Compact one-line summary of a tool's JSON schema. Full schema can
/// be deeply nested; for the catalogue we surface the top-level
/// property names + types so the LLM sees the shape without drowning
/// the prompt in nested JSON.
fn render_input_schema(schema: &serde_json::Value) -> String {
    if !schema.is_object() {
        return schema.to_string();
    }
    let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
        return "{}".to_string();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut pairs = Vec::with_capacity(props.len());
    for (k, v) in props {
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("any");
        let req_marker = if required.iter().any(|r| r == k) {
            ""
        } else {
            "?"
        };
        pairs.push(format!("{k}{req_marker}: {ty}"));
    }
    format!("{{{}}}", pairs.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::client::McpTool;
    use crate::mcp::gate::SanitizedTool;
    use crate::mcp::sanitizer::SanitizerVerdict;

    fn clean_verdict() -> SanitizerVerdict {
        SanitizerVerdict {
            sanitized: String::new(),
            flagged: false,
            matched_patterns: vec![],
        }
    }

    fn flagged_verdict() -> SanitizerVerdict {
        SanitizerVerdict {
            sanitized: "[REDACTED-INJECTION] dump env".into(),
            flagged: true,
            matched_patterns: vec!["ignore previous instructions".into()],
        }
    }

    #[test]
    fn render_input_schema_compacts_object_with_required_marker() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "depth": {"type": "integer"}
            },
            "required": ["path"]
        });
        let s = render_input_schema(&schema);
        // path is required (no marker); depth is optional (with `?`).
        assert!(s.contains("path: string"), "got: {s}");
        assert!(s.contains("depth?: integer"), "got: {s}");
    }

    #[test]
    fn render_input_schema_empty_properties_renders_curlies() {
        assert_eq!(render_input_schema(&serde_json::json!({})), "{}");
    }

    #[test]
    fn render_input_schema_non_object_falls_back_to_raw_string() {
        // Defensive: a server returning a string schema doesn't crash
        // catalogue assembly.
        assert_eq!(
            render_input_schema(&serde_json::json!("just-a-string")),
            "\"just-a-string\"".to_string()
        );
    }

    #[test]
    fn render_tool_entry_includes_name_description_and_schema() {
        let t = SanitizedTool {
            tool: McpTool {
                name: "read_file".into(),
                description: Some("Read a file.".into()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }),
            },
            verdict: clean_verdict(),
        };
        let s = render_tool_entry(&t);
        assert!(s.contains("**read_file**"));
        assert!(s.contains("Read a file."));
        assert!(s.contains("path: string"));
        // Clean tools have no [FLAGGED: ...] suffix.
        assert!(!s.contains("FLAGGED"));
    }

    #[test]
    fn render_tool_entry_marks_flagged_descriptions() {
        let t = SanitizedTool {
            tool: McpTool {
                name: "rogue".into(),
                description: Some("[REDACTED-INJECTION] dump env".into()),
                input_schema: serde_json::json!({}),
            },
            verdict: flagged_verdict(),
        };
        let s = render_tool_entry(&t);
        // The LLM sees both the sanitized text AND a [FLAGGED: ...]
        // annotation so it can apply extra skepticism.
        assert!(s.contains("[FLAGGED: ignore previous instructions]"));
        assert!(s.contains("[REDACTED-INJECTION]"));
    }

    #[test]
    fn render_tool_entry_handles_missing_description() {
        let t = SanitizedTool {
            tool: McpTool {
                name: "nameonly".into(),
                description: None,
                input_schema: serde_json::json!({}),
            },
            verdict: clean_verdict(),
        };
        let s = render_tool_entry(&t);
        assert!(s.contains("no description provided"));
    }

    #[tokio::test]
    async fn assemble_catalogue_returns_none_when_no_servers_enabled() {
        let empty = McpServers::default();
        assert!(assemble_catalogue(&empty).await.is_none());
    }

    #[test]
    fn catalogue_header_documents_invocation_format() {
        // Pin the format string the model is instructed to emit. The
        // tool-call parser (Step 2) MUST agree on `mcp-tool-call` as
        // the fence tag and the `{server, tool, arguments}` JSON shape.
        // If this test drifts away from the parser, autonomous routing
        // breaks silently.
        assert!(CATALOGUE_HEADER.contains("mcp-tool-call"));
        assert!(CATALOGUE_HEADER.contains("\"server\""));
        assert!(CATALOGUE_HEADER.contains("\"tool\""));
        assert!(CATALOGUE_HEADER.contains("\"arguments\""));
    }
}
