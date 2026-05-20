//! Parser for `mcp-tool-call` fenced JSON blocks in LLM responses.
//!
//! Step 2 of autonomous MCP routing. The catalogue (Step 1) instructs
//! the LLM to emit tool calls as:
//!
//! ```text
//! ```mcp-tool-call
//! {"server": "filesystem", "tool": "read_file", "arguments": {"path": "/tmp/x"}}
//! ```
//! ```
//!
//! This module extracts every such block from the response text and
//! returns a structured [`ParsedToolCall`] per match. Malformed blocks
//! (bad JSON, missing required field) yield a [`ParseError`] so the
//! chat loop can surface a precise diagnostic back to the LLM as a tool
//! result, letting the model self-correct on the next iteration.
//!
//! Pure-function deterministic. No I/O. The chat dispatcher pairs this
//! with [`super::gate::invoke_with_audit`] to execute the parsed calls.

use serde::{Deserialize, Serialize};

/// Fence tag the catalogue header instructs the LLM to use. Pinned
/// here so a Step 1 / Step 2 drift fails loudly via the catalogue's
/// `catalogue_header_documents_invocation_format` test.
pub const FENCE_TAG: &str = "mcp-tool-call";

/// One successfully parsed call site in the LLM response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToolCall {
    pub server: String,
    pub tool: String,
    pub arguments: serde_json::Value,
}

/// One malformed call site — the JSON inside the fence parsed wrong or
/// missed a required field. Carries the raw block + a reason so the
/// chat loop can echo it back to the LLM verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub raw_block: String,
    pub reason: String,
}

/// Outcome of scanning one response: every fence that was recognised.
/// Successful parses + parse errors are returned in the same order the
/// LLM emitted them so audit logs preserve causality.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractResult {
    pub calls: Vec<ParsedToolCall>,
    pub errors: Vec<ParseError>,
}

impl ExtractResult {
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty() && self.errors.is_empty()
    }
}

/// Strict serde shape — every field required. Optional fields would
/// open silent-failure surface (LLM emits `tool` typo → empty calls
/// arrive at the gate); the per-field `missing X` error is loud.
#[derive(Debug, Deserialize, Serialize)]
struct WireToolCall {
    server: String,
    tool: String,
    #[serde(default = "default_args")]
    arguments: serde_json::Value,
}

fn default_args() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Scan `text` for every ```mcp-tool-call ... ``` fenced block and
/// parse each as a JSON [`WireToolCall`]. Tolerant of leading/trailing
/// whitespace inside the fence and of CRLF line endings.
///
/// Order-preserving: the resulting `calls` and `errors` lists are in
/// the same order they appeared in the response, so a downstream
/// dispatcher can replay the LLM's intended sequence.
pub fn extract_tool_calls(text: &str) -> ExtractResult {
    let mut out = ExtractResult::default();
    let fence_open = format!("```{FENCE_TAG}");
    let fence_close = "```";

    let mut cursor = 0;
    while cursor < text.len() {
        let Some(open_rel) = text[cursor..].find(&fence_open) else {
            break;
        };
        let open_start = cursor + open_rel;
        // The fence tag must be followed by a newline or end-of-text
        // — otherwise a longer tag (e.g. ```mcp-tool-call-extension)
        // would false-positive.
        let after_tag = open_start + fence_open.len();
        let after_char = text[after_tag..].chars().next();
        if !matches!(after_char, Some('\n') | Some('\r') | None) {
            // Not a real opening fence — advance past it + keep scanning.
            cursor = after_tag;
            continue;
        }
        let body_start = after_tag;
        let Some(close_rel) = text[body_start..].find(fence_close) else {
            // Unterminated fence — record as one ParseError covering
            // the whole tail so the LLM sees the format issue.
            let raw = text[open_start..].to_string();
            out.errors.push(ParseError {
                raw_block: raw,
                reason: "unterminated mcp-tool-call fence (no closing ```)".to_string(),
            });
            break;
        };
        let body_end = body_start + close_rel;
        let body = text[body_start..body_end].trim();
        let raw_block = text[open_start..body_end + fence_close.len()].to_string();

        match parse_block_body(body) {
            Ok(call) => out.calls.push(call),
            Err(reason) => out.errors.push(ParseError { raw_block, reason }),
        }
        cursor = body_end + fence_close.len();
    }
    out
}

fn parse_block_body(body: &str) -> Result<ParsedToolCall, String> {
    let wire: WireToolCall = serde_json::from_str(body).map_err(|e| format!("JSON parse: {e}"))?;
    if wire.server.is_empty() {
        return Err("`server` field is empty".to_string());
    }
    if wire.tool.is_empty() {
        return Err("`tool` field is empty".to_string());
    }
    Ok(ParsedToolCall {
        server: wire.server,
        tool: wire.tool,
        arguments: wire.arguments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_tag_matches_catalogue_header_pin() {
        // Drift guard — if the fence tag is renamed, the catalogue
        // header (Step 1) must move with it.
        assert_eq!(FENCE_TAG, "mcp-tool-call");
    }

    #[test]
    fn extract_returns_empty_on_text_without_fences() {
        let r = extract_tool_calls("just regular text with no fences");
        assert!(r.is_empty());
        let r = extract_tool_calls("```python\nprint(1)\n```");
        assert!(r.is_empty(), "other fence tags must not match");
    }

    #[test]
    fn extract_finds_single_well_formed_call() {
        let text = r#"Sure, here's the file:
```mcp-tool-call
{"server": "filesystem", "tool": "read_file", "arguments": {"path": "/tmp/x"}}
```
Let me know if you need more."#;
        let r = extract_tool_calls(text);
        assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
        assert_eq!(r.calls.len(), 1);
        let c = &r.calls[0];
        assert_eq!(c.server, "filesystem");
        assert_eq!(c.tool, "read_file");
        assert_eq!(c.arguments["path"], "/tmp/x");
    }

    #[test]
    fn extract_finds_multiple_calls_in_order() {
        let text = r#"```mcp-tool-call
{"server": "a", "tool": "t1", "arguments": {"n": 1}}
```
Some intermediate text.
```mcp-tool-call
{"server": "b", "tool": "t2", "arguments": {"n": 2}}
```"#;
        let r = extract_tool_calls(text);
        assert_eq!(r.calls.len(), 2);
        assert_eq!(r.calls[0].server, "a");
        assert_eq!(r.calls[0].tool, "t1");
        assert_eq!(r.calls[1].server, "b");
        assert_eq!(r.calls[1].tool, "t2");
    }

    #[test]
    fn extract_reports_malformed_json_as_parse_error() {
        let text = r#"```mcp-tool-call
{"server": "filesystem", "tool":   // trailing comment, invalid JSON
```"#;
        let r = extract_tool_calls(text);
        assert!(r.calls.is_empty());
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].reason.contains("JSON parse"));
        // The full raw block must be preserved so the LLM can see
        // exactly what it emitted that didn't parse.
        assert!(r.errors[0].raw_block.contains("mcp-tool-call"));
    }

    #[test]
    fn extract_rejects_block_missing_server_field() {
        let text = r#"```mcp-tool-call
{"tool": "read_file", "arguments": {"path": "/tmp/x"}}
```"#;
        let r = extract_tool_calls(text);
        assert_eq!(r.errors.len(), 1);
        // serde's missing-field message includes the field name, so
        // the LLM can self-correct.
        assert!(r.errors[0].reason.contains("server"));
    }

    #[test]
    fn extract_rejects_block_with_empty_server() {
        let text = r#"```mcp-tool-call
{"server": "", "tool": "t", "arguments": {}}
```"#;
        let r = extract_tool_calls(text);
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].reason.contains("empty"));
    }

    #[test]
    fn extract_rejects_block_with_empty_tool() {
        let text = r#"```mcp-tool-call
{"server": "s", "tool": "", "arguments": {}}
```"#;
        let r = extract_tool_calls(text);
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].reason.contains("empty"));
    }

    #[test]
    fn extract_allows_missing_arguments_defaulting_to_empty_object() {
        // Tools that take no args (e.g. `list_servers`) should not be
        // forced to emit a redundant `"arguments": {}`.
        let text = r#"```mcp-tool-call
{"server": "s", "tool": "ping"}
```"#;
        let r = extract_tool_calls(text);
        assert!(r.errors.is_empty());
        assert_eq!(r.calls.len(), 1);
        assert!(r.calls[0].arguments.is_object());
    }

    #[test]
    fn extract_handles_unterminated_fence_as_one_error() {
        let text = r#"```mcp-tool-call
{"server": "s", "tool": "t"}
// no closing fence below"#;
        let r = extract_tool_calls(text);
        assert!(r.calls.is_empty());
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].reason.contains("unterminated"));
    }

    #[test]
    fn extract_does_not_match_longer_fence_tags() {
        // `mcp-tool-call-result` is the tag NEOTH will use for tool
        // RESULTS in future iterations — it must not be picked up by
        // the call parser even though it shares the prefix.
        let text = r#"```mcp-tool-call-result
{"server": "s", "tool": "t", "result": "x"}
```"#;
        let r = extract_tool_calls(text);
        assert!(
            r.is_empty(),
            "tag prefix collision: {:?} / {:?}",
            r.calls,
            r.errors
        );
    }

    #[test]
    fn extract_preserves_call_order_with_intermixed_errors() {
        let text = r#"```mcp-tool-call
{"server": "a", "tool": "t1"}
```
```mcp-tool-call
{"server": "", "tool": "broken"}
```
```mcp-tool-call
{"server": "c", "tool": "t3"}
```"#;
        let r = extract_tool_calls(text);
        assert_eq!(r.calls.len(), 2);
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.calls[0].server, "a");
        assert_eq!(r.calls[1].server, "c");
    }

    #[test]
    fn extract_tolerates_crlf_line_endings() {
        // Some LLMs emit Windows-style line endings when running in
        // certain terminals. Parser must tolerate \r\n inside fences.
        let text = "```mcp-tool-call\r\n{\"server\": \"s\", \"tool\": \"t\"}\r\n```";
        let r = extract_tool_calls(text);
        assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
        assert_eq!(r.calls.len(), 1);
    }
}
