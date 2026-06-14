//! GOLD-ADAPT-VIEW-04 — cross-agent session-transcript import.
//!
//! Parses the on-disk conversation logs of other AI coding agents (Claude
//! Code, OpenAI Codex, Gemini CLI) into a normalised [`ForeignSession`], then
//! distils each session into [`ImportedClaim`]s for `groundtruth::insert`.
//!
//! The format schemas were reverse-engineered by the agentsview project
//! (`QUELLEN/agentsview/internal/parser/`); the parsers here are a focused
//! Rust port covering the three formats the operator actually runs. Other
//! agents (iflow, kiro, …) can be added as new `parse` fns behind the
//! [`parse_session`] dispatch without touching the ingest path.
//!
//! ## Why ground-truth candidates, not episodic memory
//!
//! A one-shot CLI import has no running daemon / WAL writer, so it follows the
//! same direct-to-SQLite path as `groundtruth import-agent`: each claim is a
//! `Source::ImportSession` row that starts as `FactState::Candidate` and is
//! NOT surfaced in recall until corroborated (GOLD-ADAPT-MEM-01).

pub mod claude;
pub mod codex;
pub mod gemini;

use anyhow::Result;

use crate::memory::foreign_import::ImportedClaim;
use crate::memory::groundtruth::Source;

/// Upper bound on a single ground-truth statement (chars). Long operator
/// requests are truncated with an ellipsis so the table stays readable.
pub const MAX_STATEMENT_CHARS: usize = 600;

/// Normalised role across all foreign formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    System,
    Tool,
}

/// One normalised message from a foreign session.
#[derive(Debug, Clone)]
pub struct ForeignMessage {
    pub role: Role,
    pub text: String,
    pub model: Option<String>,
    pub timestamp: Option<String>,
}

/// Token totals across a session (best-effort; absent fields count as zero).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
}

/// A parsed foreign session, normalised across formats.
#[derive(Debug, Clone)]
pub struct ForeignSession {
    pub agent: &'static str,
    pub session_id: String,
    pub project: Option<String>,
    pub started_at: Option<String>,
    pub messages: Vec<ForeignMessage>,
    pub usage: SessionUsage,
}

/// How much of a session to turn into ground-truth claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    /// One summary row per session.
    Digest,
    /// The summary row plus one row per substantive operator request.
    Turns,
}

/// Parse a transcript `body` in the named `format`.
pub fn parse_session(body: &str, format: &str) -> Result<ForeignSession> {
    match format {
        "claude" | "claude-code" => claude::parse(body),
        "codex" => codex::parse(body),
        "gemini" => gemini::parse(body),
        other => {
            anyhow::bail!("unknown session format '{other}'. Expected: claude | codex | gemini")
        }
    }
}

/// Distil a session into ground-truth claims (always `Source::ImportSession`).
///
/// `Digest` emits a single summary row; `Turns` additionally emits one row per
/// substantive operator request (tool-result-only turns are filtered).
pub fn session_to_claims(
    session: &ForeignSession,
    scope: &str,
    granularity: Granularity,
) -> Vec<ImportedClaim> {
    let mut claims = Vec::new();

    // Substantive operator requests = user turns carrying real prose (pure
    // tool-result echoes are filtered). This is the single source of truth for
    // both the digest count and the per-turn rows, so they never disagree —
    // a Claude Code session has hundreds of user-role turns but only a handful
    // are genuine operator prompts.
    let requests: Vec<String> = session
        .messages
        .iter()
        .filter(|m| m.role == Role::User)
        .filter_map(|m| clean_request(&m.text))
        .collect();
    let n_asst = session
        .messages
        .iter()
        .filter(|m| m.role == Role::Assistant)
        .count();
    let total_tokens =
        session.usage.input_tokens + session.usage.output_tokens + session.usage.cache_read_tokens;
    let models = collect_models(session);

    let digest = format!(
        "Imported {} session {}{}{}: {} operator request(s), {} assistant repl(ies), ~{} tokens processed{}",
        session.agent,
        session.session_id,
        session
            .project
            .as_deref()
            .map(|p| format!(" in {p}"))
            .unwrap_or_default(),
        session
            .started_at
            .as_deref()
            .map(|t| format!(" started {t}"))
            .unwrap_or_default(),
        requests.len(),
        n_asst,
        total_tokens,
        if models.is_empty() {
            String::new()
        } else {
            format!(", models: {}", models.join(", "))
        },
    );
    claims.push(claim(&digest, scope));

    if granularity == Granularity::Turns {
        let id_short = short_id(&session.session_id);
        for request in &requests {
            let statement = format!("[{} {id_short}] operator request: {request}", session.agent);
            claims.push(claim(&statement, scope));
        }
    }

    claims
}

fn claim(statement: &str, scope: &str) -> ImportedClaim {
    ImportedClaim {
        statement: truncate(statement),
        scope: scope.to_string(),
        source: Source::ImportSession,
    }
}

/// Collapse a user turn into a single-line request, dropping bracketed
/// tool-token lines (`[tool_use: …]` / `[tool_result]`). Returns `None` when
/// the turn carries no real prose (e.g. a pure tool-result echo).
fn clean_request(text: &str) -> Option<String> {
    fn is_noise_line(l: &str) -> bool {
        l.is_empty() || (l.starts_with("[tool_") && l.ends_with(']'))
    }
    let kept: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !is_noise_line(l))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join(" "))
    }
}

/// Char-safe truncation with a trailing ellipsis when cut.
fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_STATEMENT_CHARS {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX_STATEMENT_CHARS - 1).collect();
    format!("{cut}…")
}

/// Short, human-recognisable session id: the last 8 chars of the id core
/// (after any `agent:` prefix).
fn short_id(id: &str) -> String {
    let core = id.rsplit(':').next().unwrap_or(id);
    let n = core.chars().count();
    if n <= 8 {
        core.to_string()
    } else {
        core.chars().skip(n - 8).collect()
    }
}

fn collect_models(session: &ForeignSession) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for m in &session.messages {
        if let Some(model) = &m.model {
            if !seen.iter().any(|s| s == model) {
                seen.push(model.clone());
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: Role, text: &str) -> ForeignMessage {
        ForeignMessage {
            role,
            text: text.to_string(),
            model: None,
            timestamp: None,
        }
    }

    fn sample() -> ForeignSession {
        ForeignSession {
            agent: "claude",
            session_id: "abcd1234efgh5678".to_string(),
            project: Some("/code/app".to_string()),
            started_at: Some("2024-01-01T10:00:00Z".to_string()),
            messages: vec![
                msg(Role::User, "Fix the login bug"),
                ForeignMessage {
                    role: Role::Assistant,
                    text: "on it".to_string(),
                    model: Some("claude-x".to_string()),
                    timestamp: None,
                },
                msg(Role::User, "[tool_result]"),
                msg(Role::User, "Now add tests"),
            ],
            usage: SessionUsage {
                input_tokens: 300,
                output_tokens: 50,
                cache_read_tokens: 300,
            },
        }
    }

    #[test]
    fn turns_granularity_emits_digest_plus_real_requests_only() {
        let claims = session_to_claims(&sample(), "session:imported", Granularity::Turns);
        // digest + 2 substantive user turns (the [tool_result] turn is filtered)
        assert_eq!(claims.len(), 3);
        assert!(claims[0].statement.contains("Imported claude session"));
        // digest count is the substantive-request count, NOT raw user turns
        assert!(claims[0].statement.contains("2 operator request(s)"));
        assert!(claims[0].statement.contains("~650 tokens processed"));
        assert!(claims[0].statement.contains("models: claude-x"));
        assert!(claims[1].statement.contains("operator request: Fix the login bug"));
        assert!(claims[2].statement.contains("operator request: Now add tests"));
        assert!(claims.iter().all(|c| c.source == Source::ImportSession));
        assert!(claims.iter().all(|c| c.scope == "session:imported"));
    }

    #[test]
    fn digest_granularity_emits_single_row() {
        let claims = session_to_claims(&sample(), "global", Granularity::Digest);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn truncate_caps_long_statements() {
        let long = "x".repeat(MAX_STATEMENT_CHARS + 50);
        let t = truncate(&long);
        assert_eq!(t.chars().count(), MAX_STATEMENT_CHARS);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn clean_request_drops_tool_only_turns() {
        assert_eq!(clean_request("[tool_result]"), None);
        assert_eq!(clean_request("[tool_use: Read]\n[tool_result]"), None);
        assert_eq!(clean_request("real request").as_deref(), Some("real request"));
        assert_eq!(clean_request("[tool_result]\nFix it").as_deref(), Some("Fix it"));
    }

    #[test]
    fn short_id_takes_last_8_after_colon() {
        assert_eq!(short_id("codex:abc-12345678"), "12345678");
        assert_eq!(short_id("xyz"), "xyz");
    }

    #[test]
    fn unknown_format_errs() {
        assert!(parse_session("{}", "iflow").is_err());
    }
}
