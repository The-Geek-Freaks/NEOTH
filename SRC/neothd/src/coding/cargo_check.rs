//! QU-05 (Session 28) — `cargo check --message-format=json` diagnostic
//! parser for the validate→fix→escalate loop.
//!
//! Smallcode runs `node --check` / a compile pass over every worker
//! patch + re-injects the diagnostics on failure. NEOTH's Rust
//! equivalent is `cargo check --message-format=json` run inside the
//! task-scoped git worktree (Pick #6 Phase 4 apply path). This module
//! is the **pure-function half**: given the captured stdout of that
//! command, extract the compiler errors + format them for re-injection
//! into the next worker attempt's prompt.
//!
//! The subprocess run itself (spawn `cargo check` in the worktree,
//! capture stdout, enforce a timeout) + the dispatcher loop that
//! re-injects + escalates after N attempts are the integration layer
//! that wires on top of this parser. Keeping the parse pure means the
//! diagnostic-extraction logic is testable against captured fixtures
//! without a toolchain — the same reason `coding::validate` is pure.
//!
//! ## Wire format
//!
//! `cargo check --message-format=json` emits newline-delimited JSON:
//! one object per line. The objects we care about carry
//! `"reason":"compiler-message"` with a nested `message` object:
//!
//! ```json
//! {"reason":"compiler-message","message":{
//!    "level":"error",
//!    "message":"cannot find value `x` in this scope",
//!    "code":{"code":"E0425"},
//!    "spans":[{"file_name":"src/main.rs","line_start":3,"is_primary":true}],
//!    "rendered":"error[E0425]: cannot find value `x`...\n --> src/main.rs:3:5"
//! }}
//! ```
//!
//! Other `reason` values (`compiler-artifact`, `build-script-executed`,
//! `build-finished`) are skipped. A malformed line (not JSON, or
//! missing fields) is skipped rather than failing the whole parse — a
//! truncated capture should still surface the diagnostics it did
//! contain.

use serde_json::Value;

/// One compiler diagnostic extracted from the JSON stream. `rendered`
/// is rustc's human-formatted block (with the `-->` location + caret
/// underlines) — the richest re-injection payload. `file` + `line`
/// come from the primary span when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDiagnostic {
    /// `"error"` / `"warning"` / `"note"` / `"help"`. We key the
    /// validate→fix loop off `error` (warnings don't block apply).
    pub level: String,
    /// Diagnostic code (`E0425`, `unused_variables`, ...) when rustc
    /// attached one. `None` for code-less messages.
    pub code: Option<String>,
    /// The short message line (without the rendered caret block).
    pub message: String,
    /// Primary span file, relative to the worktree root. `None` when
    /// the diagnostic has no primary span (rare — e.g. a crate-level
    /// error).
    pub file: Option<String>,
    /// 1-based primary-span start line.
    pub line: Option<u32>,
    /// rustc's full rendered block. Empty string when the JSON omitted
    /// it (older toolchains / synthetic frames).
    pub rendered: String,
}

impl CargoDiagnostic {
    /// True when this diagnostic is a hard error (blocks the apply).
    pub fn is_error(&self) -> bool {
        self.level == "error"
    }
}

/// Parse the captured stdout of `cargo check --message-format=json`
/// into the list of compiler diagnostics. Order-preserving (rustc
/// emits in discovery order). Non-`compiler-message` lines + malformed
/// lines are skipped silently — the caller wants the diagnostics that
/// ARE present, not a hard failure on the first artifact line.
pub fn parse_cargo_check_json(stdout: &str) -> Vec<CargoDiagnostic> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if v.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(msg) = v.get("message") else {
            continue;
        };
        // A compiler-message with no level is malformed — skip.
        let Some(level) = msg.get("level").and_then(Value::as_str) else {
            continue;
        };
        let message = msg
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let code = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let rendered = msg
            .get("rendered")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (file, line) = primary_span(msg);
        out.push(CargoDiagnostic {
            level: level.to_string(),
            code,
            message,
            file,
            line,
            rendered,
        });
    }
    out
}

/// Pull `(file_name, line_start)` from the primary span (the one with
/// `is_primary: true`). Falls back to the first span when none is
/// flagged primary (some lints don't set the flag). `(None, None)`
/// when there are no spans.
fn primary_span(message: &Value) -> (Option<String>, Option<u32>) {
    let Some(spans) = message.get("spans").and_then(Value::as_array) else {
        return (None, None);
    };
    if spans.is_empty() {
        return (None, None);
    }
    let chosen = spans
        .iter()
        .find(|s| s.get("is_primary").and_then(Value::as_bool) == Some(true))
        .unwrap_or(&spans[0]);
    let file = chosen
        .get("file_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let line = chosen
        .get("line_start")
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    (file, line)
}

/// `true` when at least one diagnostic is a hard error. The
/// validate→fix loop uses this to decide whether the patch needs a
/// fix attempt (warnings alone don't block).
pub fn has_errors(diags: &[CargoDiagnostic]) -> bool {
    diags.iter().any(CargoDiagnostic::is_error)
}

/// Filter to just the hard errors, preserving order.
pub fn errors_only(diags: &[CargoDiagnostic]) -> Vec<&CargoDiagnostic> {
    diags.iter().filter(|d| d.is_error()).collect()
}

/// Cap on how many diagnostics the retry prompt re-injects. A patch
/// that breaks 50 things should show the worker the first few — the
/// rest usually cascade from the first. Keeps the re-injected prompt
/// bounded so it doesn't blow the worker's context budget.
pub const MAX_REINJECTED_DIAGNOSTICS: usize = 5;

/// Format the error diagnostics into a retry-hint block for the next
/// worker attempt. Uses the `rendered` block when present (richest
/// signal) else falls back to `level[code]: message (file:line)`.
/// Caps at [`MAX_REINJECTED_DIAGNOSTICS`] errors + appends a
/// "+N more" line so the worker knows the list was truncated.
///
/// Returns an empty string when there are no errors (the caller
/// should not re-inject an empty hint).
pub fn format_for_retry(diags: &[CargoDiagnostic]) -> String {
    let errors = errors_only(diags);
    if errors.is_empty() {
        return String::new();
    }
    let mut buf = String::from("The patch failed `cargo check`. Fix these errors:\n\n");
    for d in errors.iter().take(MAX_REINJECTED_DIAGNOSTICS) {
        if !d.rendered.is_empty() {
            buf.push_str(&d.rendered);
            if !d.rendered.ends_with('\n') {
                buf.push('\n');
            }
        } else {
            let code = d
                .code
                .as_deref()
                .map(|c| format!("[{c}]"))
                .unwrap_or_default();
            let loc = match (&d.file, d.line) {
                (Some(f), Some(l)) => format!(" ({f}:{l})"),
                (Some(f), None) => format!(" ({f})"),
                _ => String::new(),
            };
            buf.push_str(&format!("{}{}: {}{}\n", d.level, code, d.message, loc));
        }
    }
    let total = errors.len();
    if total > MAX_REINJECTED_DIAGNOSTICS {
        buf.push_str(&format!(
            "\n…and {} more error(s) — fix the above first; many cascade.\n",
            total - MAX_REINJECTED_DIAGNOSTICS
        ));
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // One realistic compiler-message line (E0425), as `cargo check
    // --message-format=json` emits it. Trimmed of fields the parser
    // doesn't read.
    fn e0425_line() -> &'static str {
        r#"{"reason":"compiler-message","message":{"level":"error","message":"cannot find value `x` in this scope","code":{"code":"E0425"},"spans":[{"file_name":"src/main.rs","line_start":3,"is_primary":true}],"rendered":"error[E0425]: cannot find value `x` in this scope\n --> src/main.rs:3:13\n"}}"#
    }

    fn warning_line() -> &'static str {
        r#"{"reason":"compiler-message","message":{"level":"warning","message":"unused variable: `y`","code":{"code":"unused_variables"},"spans":[{"file_name":"src/lib.rs","line_start":7,"is_primary":true}],"rendered":"warning: unused variable: `y`\n"}}"#
    }

    #[test]
    fn parses_single_error() {
        let diags = parse_cargo_check_json(e0425_line());
        assert_eq!(diags.len(), 1);
        let d = &diags[0];
        assert_eq!(d.level, "error");
        assert_eq!(d.code.as_deref(), Some("E0425"));
        assert!(d.message.contains("cannot find value"));
        assert_eq!(d.file.as_deref(), Some("src/main.rs"));
        assert_eq!(d.line, Some(3));
        assert!(d.rendered.contains("E0425"));
        assert!(d.is_error());
    }

    #[test]
    fn skips_non_compiler_message_lines() {
        let stream = format!(
            "{}\n{}\n{}",
            r#"{"reason":"compiler-artifact","target":{"name":"neothd"}}"#,
            e0425_line(),
            r#"{"reason":"build-finished","success":false}"#,
        );
        let diags = parse_cargo_check_json(&stream);
        assert_eq!(diags.len(), 1, "only the compiler-message counts");
        assert_eq!(diags[0].code.as_deref(), Some("E0425"));
    }

    #[test]
    fn skips_malformed_lines_without_failing_whole_parse() {
        let stream = format!(
            "{}\n{}\n{}",
            "not json at all {{{",
            e0425_line(),
            r#"{"reason":"compiler-message"}"#, // missing message → skip
        );
        let diags = parse_cargo_check_json(&stream);
        assert_eq!(diags.len(), 1, "the one good line survives");
    }

    #[test]
    fn handles_empty_and_whitespace_input() {
        assert!(parse_cargo_check_json("").is_empty());
        assert!(parse_cargo_check_json("\n\n   \n").is_empty());
    }

    #[test]
    fn has_errors_distinguishes_error_from_warning() {
        let only_warn = parse_cargo_check_json(warning_line());
        assert!(!has_errors(&only_warn), "a lone warning is not a hard error");
        let with_error = parse_cargo_check_json(&format!("{}\n{}", warning_line(), e0425_line()));
        assert!(has_errors(&with_error));
    }

    #[test]
    fn errors_only_filters_warnings() {
        let mixed = parse_cargo_check_json(&format!("{}\n{}", warning_line(), e0425_line()));
        let errs = errors_only(&mixed);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].code.as_deref(), Some("E0425"));
    }

    #[test]
    fn primary_span_prefers_is_primary_true() {
        // Two spans; the non-primary one comes first. Parser must pick
        // the primary (line 42), not the first (line 1).
        let line = r#"{"reason":"compiler-message","message":{"level":"error","message":"mismatched types","spans":[{"file_name":"a.rs","line_start":1,"is_primary":false},{"file_name":"b.rs","line_start":42,"is_primary":true}],"rendered":"x"}}"#;
        let diags = parse_cargo_check_json(line);
        assert_eq!(diags[0].file.as_deref(), Some("b.rs"));
        assert_eq!(diags[0].line, Some(42));
    }

    #[test]
    fn primary_span_falls_back_to_first_when_none_primary() {
        let line = r#"{"reason":"compiler-message","message":{"level":"error","message":"x","spans":[{"file_name":"a.rs","line_start":5,"is_primary":false}],"rendered":"x"}}"#;
        let diags = parse_cargo_check_json(line);
        assert_eq!(diags[0].file.as_deref(), Some("a.rs"));
        assert_eq!(diags[0].line, Some(5));
    }

    #[test]
    fn diagnostic_without_spans_has_none_location() {
        let line = r#"{"reason":"compiler-message","message":{"level":"error","message":"crate-level error","spans":[],"rendered":"error: crate-level error"}}"#;
        let diags = parse_cargo_check_json(line);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].file, None);
        assert_eq!(diags[0].line, None);
    }

    #[test]
    fn format_for_retry_empty_when_no_errors() {
        let only_warn = parse_cargo_check_json(warning_line());
        assert_eq!(format_for_retry(&only_warn), "");
    }

    #[test]
    fn format_for_retry_uses_rendered_block() {
        let diags = parse_cargo_check_json(e0425_line());
        let hint = format_for_retry(&diags);
        assert!(hint.contains("failed `cargo check`"));
        assert!(hint.contains("E0425"), "rendered block must carry the code");
    }

    #[test]
    fn format_for_retry_falls_back_to_message_when_no_rendered() {
        let line = r#"{"reason":"compiler-message","message":{"level":"error","message":"borrow of moved value","code":{"code":"E0382"},"spans":[{"file_name":"m.rs","line_start":9,"is_primary":true}],"rendered":""}}"#;
        let diags = parse_cargo_check_json(line);
        let hint = format_for_retry(&diags);
        assert!(hint.contains("error[E0382]: borrow of moved value (m.rs:9)"));
    }

    #[test]
    fn format_for_retry_caps_and_reports_overflow() {
        // Build MAX+3 errors; the hint shows MAX + an "…and 3 more".
        let mut lines = Vec::new();
        for i in 0..(MAX_REINJECTED_DIAGNOSTICS + 3) {
            lines.push(format!(
                r#"{{"reason":"compiler-message","message":{{"level":"error","message":"err {i}","spans":[{{"file_name":"f.rs","line_start":{i},"is_primary":true}}],"rendered":"error: err {i}\n"}}}}"#
            ));
        }
        let diags = parse_cargo_check_json(&lines.join("\n"));
        assert_eq!(diags.len(), MAX_REINJECTED_DIAGNOSTICS + 3);
        let hint = format_for_retry(&diags);
        assert!(hint.contains("…and 3 more error(s)"));
    }

    #[test]
    fn constants_canonical() {
        assert_eq!(MAX_REINJECTED_DIAGNOSTICS, 5);
    }
}
