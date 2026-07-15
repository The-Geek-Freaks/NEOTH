//! Claude Code transcript parser — `~/.claude/projects/**/<uuid>.jsonl`.
//!
//! JSONL, one entry per line; the root `type` field is the role. Ported from
//! the schema agentsview reverse-engineered (`internal/parser/claude.go`).
//! Simplifications vs the original (acceptable for read-only candidate ingest):
//! DAG forks are read linearly (a forked file's branches merge into one
//! session) and incremental resume is not needed (we always read the whole
//! file).

use anyhow::Result;
use serde_json::Value;

use super::{ForeignMessage, ForeignSession, Role, SessionUsage};

pub fn parse(body: &str) -> Result<ForeignSession> {
    let mut messages = Vec::new();
    let mut usage = SessionUsage::default();
    let mut session_id = String::new();
    let mut project: Option<String> = None;
    let mut started_at: Option<String> = None;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Invalid JSON lines are silently skipped (matches agentsview).
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };

        if session_id.is_empty()
            && let Some(s) = v.get("sessionId").and_then(Value::as_str)
        {
            session_id = s.to_string();
        }

        let ty = v.get("type").and_then(Value::as_str).unwrap_or("");
        let ts = v
            .get("timestamp")
            .and_then(Value::as_str)
            .map(str::to_string);
        if started_at.is_none() {
            started_at = ts.clone();
        }
        if ty == "user" && project.is_none() {
            project = v.get("cwd").and_then(Value::as_str).map(str::to_string);
        }

        // Skip metadata + compact-summary boundary entries (not real turns).
        if v.get("isMeta").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        if v.get("isCompactSummary")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }

        let role = match ty {
            "user" => Role::User,
            "assistant" => Role::Assistant,
            // system / attachment / progress / queue-operation — not turns.
            _ => continue,
        };

        let message = v.get("message");
        let model = message
            .and_then(|m| m.get("model"))
            .and_then(Value::as_str)
            .map(str::to_string);

        if let Some(u) = message.and_then(|m| m.get("usage")) {
            usage.input_tokens += u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
            usage.input_tokens += u
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            usage.cache_read_tokens += u
                .get("cache_read_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            usage.output_tokens += u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
        }

        let text = message
            .map(|m| extract_content(m.get("content")))
            .unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        messages.push(ForeignMessage {
            role,
            text,
            model,
            timestamp: ts,
        });
    }

    if session_id.is_empty() {
        session_id = "unknown".to_string();
    }
    Ok(ForeignSession {
        agent: "claude",
        session_id,
        project,
        started_at,
        messages,
        usage,
    })
}

/// User `content` is a plain string; assistant `content` is an array of typed
/// blocks. Tool calls become `[tool_use: name]` markers; thinking is dropped.
fn extract_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => {
            let mut parts: Vec<String> = Vec::new();
            for b in blocks {
                match b.get("type").and_then(Value::as_str).unwrap_or("") {
                    "text" => {
                        if let Some(t) = b.get("text").and_then(Value::as_str) {
                            parts.push(t.to_string());
                        }
                    }
                    "tool_use" => {
                        let name = b.get("name").and_then(Value::as_str).unwrap_or("tool");
                        parts.push(format!("[tool_use: {name}]"));
                    }
                    "tool_result" => parts.push("[tool_result]".to_string()),
                    // "thinking" and unknown blocks are dropped.
                    _ => {}
                }
            }
            parts.join("\n")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_string_and_assistant_blocks_with_usage() {
        let body = "{\"type\":\"user\",\"timestamp\":\"2024-01-01T10:00:00Z\",\"message\":{\"content\":\"Fix the login bug\"},\"cwd\":\"/code/app\"}\n{\"type\":\"assistant\",\"timestamp\":\"2024-01-01T10:00:05Z\",\"message\":{\"model\":\"claude-sonnet-4\",\"content\":[{\"type\":\"text\",\"text\":\"Looking at auth\"},{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"Read\",\"input\":{}}],\"usage\":{\"input_tokens\":100,\"output_tokens\":50,\"cache_creation_input_tokens\":200,\"cache_read_input_tokens\":300}}}";
        let s = parse(body).unwrap();
        assert_eq!(s.agent, "claude");
        assert_eq!(s.project.as_deref(), Some("/code/app"));
        assert_eq!(s.messages.len(), 2);
        assert_eq!(s.messages[0].role, Role::User);
        assert_eq!(s.messages[0].text, "Fix the login bug");
        assert_eq!(s.messages[1].role, Role::Assistant);
        assert_eq!(s.messages[1].text, "Looking at auth\n[tool_use: Read]");
        assert_eq!(s.messages[1].model.as_deref(), Some("claude-sonnet-4"));
        // input 100 + cache_creation 200 = 300; cache_read 300; output 50
        assert_eq!(s.usage.input_tokens, 300);
        assert_eq!(s.usage.cache_read_tokens, 300);
        assert_eq!(s.usage.output_tokens, 50);
    }

    #[test]
    fn skips_invalid_and_meta_lines() {
        let body = "not json\n{\"type\":\"user\",\"isMeta\":true,\"message\":{\"content\":\"meta\"}}\n{\"type\":\"user\",\"message\":{\"content\":\"real\"}}";
        let s = parse(body).unwrap();
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.messages[0].text, "real");
    }
}
