//! GOLD-ADOPT-17 — Schema-driven mid-turn elicitation.
//!
//! When an MCP tool result carries an `elicitation_request` key, NEOTH
//! intercepts the rendered output BEFORE it is injected into the next
//! LLM prompt and presents the operator with a structured CLI form.
//! The collected answers are injected as an additional tool-result block
//! and the loop continues with both the original result AND the answers
//! in context.
//!
//! ## Design constraints
//!
//! * **TTY-only.** `ElicitationHandler::Disabled` silently skips the
//!   intercept. The channel/serve-pipeline path MUST use `Disabled` —
//!   there is no TTY to prompt on, and blocking an async task on a
//!   dialoguer read would deadlock.
//!
//! * **Privacy.** WAL frames store field *names* only, NEVER values —
//!   values can be passwords, tokens, or PII.  The schema is also NOT
//!   stored; only `field_count` and the answered field name list.
//!
//! * **`spawn_blocking`.** dialoguer prompts are sync-blocking; wrapping
//!   in `tokio::task::spawn_blocking` prevents stalling the async executor.
//!
//! * **Batchable WAL frames.** 0x03 / 0x04 are advisory and re-askable
//!   on crash (the operator sees the prompt again on restart), so they
//!   are NOT in the `needs_immediate_sync` deny-list.

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

// ── WAL event codes ─────────────────────────────────────────────────────────
use crate::wal::events::{EVENT_TYPE_ELICITATION_REQUESTED, EVENT_TYPE_ELICITATION_RESPONSE};

// ── Public surface ───────────────────────────────────────────────────────────

/// Controls whether mid-turn elicitation prompts are shown to the operator.
#[derive(Clone, Debug, Default)]
pub enum ElicitationHandler {
    /// Prompt the operator on the terminal (TTY path: `neoth chat`).
    Cli,
    /// Silently skip elicitation (channel / serve-pipeline path, tests).
    #[default]
    Disabled,
}

impl ElicitationHandler {
    /// Convenience constructor used by call-sites that forward a reference.
    pub fn disabled() -> Self {
        Self::Disabled
    }
}

// ── Internal wire-format ─────────────────────────────────────────────────────

/// Wire shape emitted by an MCP tool that wants to collect operator input.
///
/// Tools signal an elicitation request by embedding this structure under
/// the key `"elicitation_request"` in their JSON result.  Any additional
/// keys in the tool result are passed through unchanged.
///
/// Example:
/// ```json
/// {
///   "status": "needs_input",
///   "elicitation_request": {
///     "title": "Configure target",
///     "description": "Please provide scan parameters",
///     "properties": {
///       "target_host": { "type": "string", "description": "Host to scan" },
///       "aggressive":  { "type": "boolean", "description": "Run in aggressive mode?" },
///       "scan_type":   { "type": "string",  "enum": ["quick","full","stealth"],
///                        "description": "Scan profile" }
///     }
///   }
/// }
/// ```
#[derive(Debug, Deserialize)]
struct ElicitationRequest {
    title: Option<String>,
    description: Option<String>,
    /// JSON-Schema-like property map.  Only `type`, `enum`, and
    /// `description` are inspected; unknown keys are silently ignored.
    #[serde(default)]
    properties: HashMap<String, PropertySchema>,
}

#[derive(Debug, Deserialize)]
struct PropertySchema {
    #[cfg(feature = "wizard")]
    #[serde(rename = "type")]
    ty: Option<String>,
    #[cfg(feature = "wizard")]
    #[serde(rename = "enum")]
    variants: Option<Vec<String>>,
    #[cfg(feature = "wizard")]
    description: Option<String>,
}

/// Container that holds a rendered tool result with a possible embedded
/// elicitation request.
#[derive(Deserialize)]
struct ToolResultEnvelope {
    elicitation_request: Option<ElicitationRequest>,
}

// ── Main entry point ─────────────────────────────────────────────────────────

/// Called inside the dispatch loop's `Ok(rendered)` arm, after
/// `maybe_skeletonize` and before typed prompt serialization.
///
/// Returns `Some(answer_block)` when the operator filled in the form;
/// the caller appends this string to `tool_result_blocks` so the next
/// LLM turn sees both the original rendered output AND the answers.
///
/// Returns `None` when:
/// - `handler` is `Disabled`, OR
/// - `rendered` contains no `"elicitation_request"` substring, OR
/// - parsing fails (non-JSON tool output, malformed schema), OR
/// - the operator presses Ctrl-C / ESC.
pub async fn maybe_elicit(
    rendered: &str,
    server: &str,
    tool: &str,
    handler: &ElicitationHandler,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<Option<String>> {
    // Fast-path: bail before any allocation on the common case.
    if matches!(handler, ElicitationHandler::Disabled) {
        return Ok(None);
    }
    if !rendered.contains("elicitation_request") {
        return Ok(None);
    }

    // Parse — `.ok()` so spurious matches in prose don't abort the loop.
    let envelope: ToolResultEnvelope = match serde_json::from_str(rendered) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let req = match envelope.elicitation_request {
        Some(r) => r,
        None => return Ok(None),
    };
    if req.properties.is_empty() {
        return Ok(None);
    }

    // Emit WAL 0x03 ELICITATION_REQUESTED (field names only, no values).
    let field_names: Vec<String> = req.properties.keys().cloned().collect();
    emit_elicitation_wal(
        writer,
        server,
        tool,
        EVENT_TYPE_ELICITATION_REQUESTED,
        &field_names,
        None,
    )
    .await;

    // Render header.
    let title = req.title.as_deref().unwrap_or("Operator input requested");
    eprintln!("\n\x1b[1;36m[NEOTH] {title}\x1b[0m");
    if let Some(desc) = &req.description {
        eprintln!("  {desc}");
    }
    eprintln!();

    // Collect answers — spawn_blocking because dialoguer is sync.
    // Build an owned copy of properties for the blocking closure.
    let props_owned: Vec<(String, PropertySchema)> = req.properties.into_iter().collect();
    let answers_result = tokio::task::spawn_blocking(move || {
        let mut answers: Vec<(String, String)> = Vec::with_capacity(props_owned.len());
        for (name, schema) in &props_owned {
            match prompt_for_property(name, schema) {
                Some(val) => answers.push((name.clone(), val)),
                None => return None, // user aborted
            }
        }
        Some(answers)
    })
    .await?;

    let answers = match answers_result {
        Some(a) if !a.is_empty() => a,
        _ => return Ok(None),
    };

    // Emit WAL 0x04 ELICITATION_RESPONSE (answered field names only).
    let answered_names: Vec<String> = answers.iter().map(|(k, _)| k.clone()).collect();
    emit_elicitation_wal(
        writer,
        server,
        tool,
        EVENT_TYPE_ELICITATION_RESPONSE,
        &field_names,
        Some(&answered_names),
    )
    .await;

    // Build an answer block the LLM can parse.
    let mut json_obj = serde_json::Map::new();
    for (k, v) in &answers {
        json_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    let answer_json = serde_json::to_string_pretty(&serde_json::Value::Object(json_obj))
        .unwrap_or_else(|_| "{}".to_string());

    let block = format!(
        "```mcp-elicitation-response\n\
         server: {server}\ntool: {tool}\nanswers:\n{answer_json}\n```"
    );
    Ok(Some(block))
}

// ── Sync prompt helper (runs inside spawn_blocking) ─────────────────────────

/// Present a single property to the operator via dialoguer.
/// Returns the collected string value, or `None` if the user aborted.
#[cfg(feature = "wizard")]
fn prompt_for_property(name: &str, schema: &PropertySchema) -> Option<String> {
    let label = match &schema.description {
        Some(d) => format!("{name} — {d}"),
        None => name.to_string(),
    };

    // Boolean → Confirm
    if schema.ty.as_deref() == Some("boolean") {
        let answer = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(&label)
            .default(false)
            .interact_opt()
            .ok()??;
        return Some(if answer { "true" } else { "false" }.to_string());
    }

    // Enum → Select
    if let Some(variants) = &schema.variants
        && !variants.is_empty()
    {
        let idx = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(&label)
            .items(variants)
            .default(0)
            .interact_opt()
            .ok()??;
        return Some(variants[idx].clone());
    }

    // Default → free-text Input
    let val = dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(&label)
        .allow_empty(true)
        .interact_text()
        .ok()?;
    Some(val)
}

/// Slim daemon builds intentionally omit dialoguer with the `wizard` feature.
/// If such a binary reaches an interactive elicitation request, fail closed:
/// inject no fabricated answer and make the missing capability visible.
#[cfg(not(feature = "wizard"))]
fn prompt_for_property(_name: &str, _schema: &PropertySchema) -> Option<String> {
    tracing::warn!(
        "interactive MCP elicitation requires a build with the `wizard` feature; request left unanswered"
    );
    None
}

// ── WAL helper ───────────────────────────────────────────────────────────────

async fn emit_elicitation_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    server: &str,
    tool: &str,
    event_type: u8,
    field_names: &[String],
    answered_fields: Option<&[String]>,
) {
    let writer = match writer {
        Some(w) => w,
        None => return,
    };
    let mut payload = serde_json::json!({
        "server": server,
        "tool": tool,
        "field_count": field_names.len(),
        "fields": field_names,
        "ts_unix": crate::time::now_unix_i64(),
    });
    if let Some(answered) = answered_fields {
        payload["answered_fields"] = serde_json::json!(answered);
        payload["answered_count"] = serde_json::json!(answered.len());
    }
    let payload_bytes = serde_json::to_vec(&payload)
        .expect("elicitation audit payload contains only infallible JSON values");
    let header = crate::wal::HeaderBuilder::new(event_type, &payload_bytes).build();
    // ponytail: fire-and-forget WAL write; loss on crash is acceptable
    // (batchable frames, operator re-asked on restart).
    if let Err(e) = writer.append(header, payload_bytes).await {
        tracing::warn!(error = %e, event_type, "elicitation WAL append failed");
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_handler_never_elicits() {
        // Even with a valid elicitation_request payload, Disabled returns None.
        let rendered = r#"{
            "status": "needs_input",
            "elicitation_request": {
                "title": "Test",
                "properties": {
                    "host": { "type": "string", "description": "Target host" }
                }
            }
        }"#;
        let result = maybe_elicit(
            rendered,
            "test_server",
            "test_tool",
            &ElicitationHandler::Disabled,
            None,
        )
        .await
        .unwrap();
        assert!(result.is_none(), "Disabled handler must return None");
    }

    #[tokio::test]
    async fn fast_path_no_keyword() {
        // Non-JSON tool output without the sentinel substring: instant None.
        let rendered = "The file has been written successfully.";
        let result = maybe_elicit(
            rendered,
            "fs",
            "write_file",
            &ElicitationHandler::Disabled,
            None,
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn non_json_with_keyword_in_prose() {
        // Prose that contains "elicitation_request" substring but is not JSON:
        // parse fails silently, returns None.
        let rendered = "The elicitation_request was processed. No further action needed.";
        let result = maybe_elicit(rendered, "srv", "tool", &ElicitationHandler::Cli, None)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "parse failure on prose must return None silently"
        );
    }

    #[tokio::test]
    async fn json_without_elicitation_key() {
        // Valid JSON but no elicitation_request key → None.
        let rendered = r#"{"status":"ok","result":42}"#;
        let result = maybe_elicit(rendered, "srv", "tool", &ElicitationHandler::Disabled, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn json_with_null_elicitation_request() {
        // elicitation_request explicitly null → None.
        let rendered = r#"{"elicitation_request": null}"#;
        let result = maybe_elicit(rendered, "srv", "tool", &ElicitationHandler::Cli, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn json_with_empty_properties() {
        // elicitation_request with no properties → None (nothing to ask).
        let rendered = r#"{"elicitation_request": {"title": "Hi", "properties": {}}}"#;
        let result = maybe_elicit(rendered, "srv", "tool", &ElicitationHandler::Cli, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    /// Verify `ElicitationHandler::default()` is `Disabled`.
    #[test]
    fn default_is_disabled() {
        assert!(matches!(
            ElicitationHandler::default(),
            ElicitationHandler::Disabled
        ));
    }
}
