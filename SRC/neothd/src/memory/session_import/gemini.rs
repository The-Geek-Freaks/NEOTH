//! Gemini CLI transcript parser — `~/.gemini/tmp/<hash>/chats/session-*.json`.
//!
//! Dual format: a single JSON document (`{sessionId, messages:[…]}`) OR a
//! live-appended JSONL file with the same extension. Ported from the schema
//! agentsview reverse-engineered (`internal/parser/gemini.go`). The assistant
//! role discriminator is `"gemini"`; tool calls + results are inline in the
//! same message's `toolCalls` array.

use anyhow::Result;
use serde_json::Value;

use super::{ForeignMessage, ForeignSession, Role, SessionUsage};

pub fn parse(body: &str) -> Result<ForeignSession> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            if v.get("messages").map(Value::is_array).unwrap_or(false)
                || v.get("sessionId").is_some()
            {
                return Ok(parse_document(&v));
            }
        }
    }
    Ok(parse_jsonl(body))
}

fn parse_document(v: &Value) -> ForeignSession {
    let session_id = v
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let started_at = v
        .get("startTime")
        .and_then(Value::as_str)
        .map(str::to_string);
    let project = v
        .get("projectHash")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut messages = Vec::new();
    let mut usage = SessionUsage::default();
    if let Some(arr) = v.get("messages").and_then(Value::as_array) {
        for m in arr {
            accumulate_usage(m, &mut usage);
            if let Some(msg) = message_from(m) {
                messages.push(msg);
            }
        }
    }
    ForeignSession {
        agent: "gemini",
        session_id: format!("gemini:{session_id}"),
        project,
        started_at,
        messages,
        usage,
    }
}

fn parse_jsonl(body: &str) -> ForeignSession {
    let mut session_id = String::new();
    let mut started_at: Option<String> = None;
    let mut project: Option<String> = None;
    let mut usage = SessionUsage::default();
    // (id, message) — a later record with the same non-empty id replaces the
    // earlier one in place (Gemini's live-append dedup semantics).
    let mut ordered: Vec<(String, ForeignMessage)> = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if session_id.is_empty() {
            if let Some(s) = v.get("sessionId").and_then(Value::as_str) {
                session_id = s.to_string();
            }
        }
        if started_at.is_none() {
            started_at = v
                .get("startTime")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if project.is_none() {
            project = v
                .get("projectHash")
                .and_then(Value::as_str)
                .map(str::to_string);
        }

        if matches!(
            v.get("type").and_then(Value::as_str),
            Some("user") | Some("gemini")
        ) {
            accumulate_usage(&v, &mut usage);
            if let Some(msg) = message_from(&v) {
                let id = v
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if !id.is_empty() {
                    if let Some(slot) = ordered.iter_mut().find(|(eid, _)| *eid == id) {
                        slot.1 = msg;
                        continue;
                    }
                }
                ordered.push((id, msg));
            }
        }
    }

    if session_id.is_empty() {
        session_id = "unknown".to_string();
    }
    ForeignSession {
        agent: "gemini",
        session_id: format!("gemini:{session_id}"),
        project,
        started_at,
        messages: ordered.into_iter().map(|(_, m)| m).collect(),
        usage,
    }
}

fn message_from(v: &Value) -> Option<ForeignMessage> {
    let role = match v.get("type").and_then(Value::as_str)? {
        "user" => Role::User,
        "gemini" => Role::Assistant,
        _ => return None,
    };
    let mut text = extract_content(v.get("content"));
    if let Some(calls) = v.get("toolCalls").and_then(Value::as_array) {
        for c in calls {
            let name = c.get("name").and_then(Value::as_str).unwrap_or("tool");
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&format!("[tool_use: {name}]"));
        }
    }
    if text.trim().is_empty() {
        return None;
    }
    Some(ForeignMessage {
        role,
        text,
        model: v.get("model").and_then(Value::as_str).map(str::to_string),
        timestamp: v
            .get("timestamp")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Gemini `content` is a string or an array of `{text}` parts.
fn extract_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str).map(str::to_string))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Gemini per-message `tokens` object: `{input, output, cached, thoughts}`.
/// Thinking tokens are billed at the output rate, so they fold into output.
fn accumulate_usage(m: &Value, usage: &mut SessionUsage) {
    if let Some(t) = m.get("tokens") {
        usage.input_tokens += t.get("input").and_then(Value::as_u64).unwrap_or(0);
        usage.output_tokens += t.get("output").and_then(Value::as_u64).unwrap_or(0);
        usage.output_tokens += t.get("thoughts").and_then(Value::as_u64).unwrap_or(0);
        usage.cache_read_tokens += t.get("cached").and_then(Value::as_u64).unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_json_document() {
        let body = "{\"lastUpdated\":\"t1\",\"messages\":[{\"content\":\"Fix the login bug\",\"id\":\"u1\",\"timestamp\":\"t0\",\"type\":\"user\"},{\"content\":\"Let me read it.\",\"id\":\"a1\",\"model\":\"gemini-2.5-pro\",\"timestamp\":\"t1\",\"toolCalls\":[{\"args\":{},\"displayName\":\"ReadFile\",\"name\":\"read_file\",\"status\":\"success\"}],\"type\":\"gemini\",\"tokens\":{\"input\":120,\"output\":40,\"cached\":0,\"thoughts\":10}}],\"projectHash\":\"abc123\",\"sessionId\":\"xyz789\",\"startTime\":\"t0\"}";
        let s = parse(body).unwrap();
        assert_eq!(s.session_id, "gemini:xyz789");
        assert_eq!(s.project.as_deref(), Some("abc123"));
        assert_eq!(s.messages.len(), 2);
        assert_eq!(s.messages[0].text, "Fix the login bug");
        assert_eq!(s.messages[1].text, "Let me read it.\n[tool_use: read_file]");
        assert_eq!(s.messages[1].model.as_deref(), Some("gemini-2.5-pro"));
        // input 120; output 40 + thoughts 10 = 50; cached 0
        assert_eq!(s.usage.input_tokens, 120);
        assert_eq!(s.usage.output_tokens, 50);
    }

    #[test]
    fn parses_jsonl_with_dedup_replace() {
        let body = "{\"sessionId\":\"live1\",\"startTime\":\"t0\"}\n{\"type\":\"user\",\"id\":\"u1\",\"content\":\"first\"}\n{\"type\":\"user\",\"id\":\"u1\",\"content\":\"first-edited\"}";
        let s = parse(body).unwrap();
        assert_eq!(s.session_id, "gemini:live1");
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.messages[0].text, "first-edited");
    }
}
