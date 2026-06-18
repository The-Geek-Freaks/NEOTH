//! OpenAI Codex transcript parser — `~/.codex/sessions/**/rollout-*.jsonl`.
//!
//! Every line is a `{type, payload, timestamp}` envelope. Ported from the
//! schema agentsview reverse-engineered (`internal/parser/codex.go`). Two
//! gotchas baked in: token usage arrives in a separate `event_msg`
//! (`token_count`), and Codex `input_tokens` INCLUDES cached tokens, so the
//! uncached count is `input - cached`.

use anyhow::Result;
use serde_json::Value;

use super::{ForeignMessage, ForeignSession, Role, SessionUsage};

pub fn parse(body: &str) -> Result<ForeignSession> {
    let mut messages = Vec::new();
    let mut usage = SessionUsage::default();
    let mut session_id = String::new();
    let mut project: Option<String> = None;
    let mut model: Option<String> = None;
    let mut started_at: Option<String> = None;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ts = v
            .get("timestamp")
            .and_then(Value::as_str)
            .map(str::to_string);
        if started_at.is_none() {
            started_at = ts.clone();
        }
        let payload = v.get("payload");

        match v.get("type").and_then(Value::as_str).unwrap_or("") {
            "session_meta" => {
                if let Some(p) = payload {
                    if session_id.is_empty() {
                        if let Some(id) = p.get("id").and_then(Value::as_str) {
                            session_id = format!("codex:{id}");
                        }
                    }
                    if project.is_none() {
                        project = p.get("cwd").and_then(Value::as_str).map(str::to_string);
                    }
                    if model.is_none() {
                        model = p.get("model").and_then(Value::as_str).map(str::to_string);
                    }
                }
            }
            "turn_context" => {
                if let Some(m) = payload.and_then(|p| p.get("model")).and_then(Value::as_str) {
                    model = Some(m.to_string());
                }
            }
            "response_item" => {
                let Some(p) = payload else {
                    continue;
                };
                match p.get("type").and_then(Value::as_str).unwrap_or("") {
                    "function_call" => {
                        let name = p.get("name").and_then(Value::as_str).unwrap_or("tool");
                        messages.push(ForeignMessage {
                            role: Role::Assistant,
                            text: format!("[tool_use: {name}]"),
                            model: model.clone(),
                            timestamp: ts,
                        });
                    }
                    "function_call_output" => {
                        messages.push(ForeignMessage {
                            role: Role::Tool,
                            text: "[tool_result]".to_string(),
                            model: None,
                            timestamp: ts,
                        });
                    }
                    _ => {
                        let role = match p.get("role").and_then(Value::as_str) {
                            Some("user") => Role::User,
                            Some("assistant") => Role::Assistant,
                            _ => continue,
                        };
                        let text = extract_content(p.get("content"));
                        if text.trim().is_empty() {
                            continue;
                        }
                        messages.push(ForeignMessage {
                            role,
                            text,
                            model: model.clone(),
                            timestamp: ts,
                        });
                    }
                }
            }
            "event_msg" => {
                if let Some(p) = payload {
                    if p.get("type").and_then(Value::as_str) == Some("token_count") {
                        if let Some(tu) = p.get("info").and_then(|i| i.get("last_token_usage")) {
                            let input = tu.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
                            let cached = tu
                                .get("cached_input_tokens")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let output =
                                tu.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
                            usage.input_tokens += input.saturating_sub(cached);
                            usage.cache_read_tokens += cached;
                            usage.output_tokens += output;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if session_id.is_empty() {
        session_id = "codex:unknown".to_string();
    }
    Ok(ForeignSession {
        agent: "codex",
        session_id,
        project,
        started_at,
        messages,
        usage,
    })
}

/// Codex `content` is an array of `{type, text}` blocks (input_text /
/// output_text / text). Concatenate the text fields.
fn extract_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str).map(str::to_string))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_envelope_with_meta_message_call_and_backfilled_tokens() {
        let body = "{\"payload\":{\"cwd\":\"/code/api\",\"id\":\"abc-123\",\"originator\":\"user\"},\"timestamp\":\"2024-01-01T10:00:00Z\",\"type\":\"session_meta\"}\n{\"payload\":{\"content\":[{\"text\":\"Add rate limiting\",\"type\":\"input_text\"}],\"role\":\"user\"},\"timestamp\":\"2024-01-01T10:00:01Z\",\"type\":\"response_item\"}\n{\"payload\":{\"call_id\":\"c1\",\"name\":\"shell_command\",\"summary\":\"run\",\"type\":\"function_call\"},\"timestamp\":\"2024-01-01T10:00:05Z\",\"type\":\"response_item\"}\n{\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":{\"input_tokens\":500,\"cached_input_tokens\":100,\"output_tokens\":80}}},\"timestamp\":\"2024-01-01T10:00:06Z\",\"type\":\"event_msg\"}";
        let s = parse(body).unwrap();
        assert_eq!(s.session_id, "codex:abc-123");
        assert_eq!(s.project.as_deref(), Some("/code/api"));
        assert_eq!(s.messages.len(), 2);
        assert_eq!(s.messages[0].role, Role::User);
        assert_eq!(s.messages[0].text, "Add rate limiting");
        assert_eq!(s.messages[1].text, "[tool_use: shell_command]");
        // 500 total - 100 cached = 400 uncached; 100 cache_read; 80 output
        assert_eq!(s.usage.input_tokens, 400);
        assert_eq!(s.usage.cache_read_tokens, 100);
        assert_eq!(s.usage.output_tokens, 80);
    }
}
