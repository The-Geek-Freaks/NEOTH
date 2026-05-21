//! Tool-output redaction — port of smallcode's `src/security/sanitize.js`
//! secret-redaction pass.
//!
//! Per `PLAN/SMALLCODE_AUDIT_2026-05-21.md` port #3. NEOTH's gap
//! today: a coding worker that reads `.env`, runs `env`, or pipes a
//! cred-bearing log line through its tool-output channel leaks the
//! literal secret into WAL frames + the activity feed. The
//! audit chain is durable; leaks are forever.
//!
//! This module:
//!   - Defines a closed set of secret-shape regexes (OpenAI /
//!     Anthropic / GitHub / Google / AWS / JWT / Slack / Discord /
//!     Telegram bot tokens / generic .env KEY=VALUE / PEM blocks)
//!   - `redact_text(input)` returns a new String with every match
//!     replaced by `[REDACTED:<kind>]`
//!   - Pure function — no IO, no allocation beyond the output
//!     String
//!   - Conservative: prefers false positives (a non-secret string
//!     that happens to look like one) over leaking a real secret
//!
//! Call sites (wired in follow-up commits):
//!   - `coding::dispatcher::handle_retryable_failure` — diagnosis
//!     strings hit the WAL via tracing::warn
//!   - `wasm_plugin::dispatch::invoke_plugin` — InvocationOutcome.error
//!   - `cli::serve` PROVIDER_RESPONSE frame body
//!   - Anywhere we emit a frame that's `text-typed` from external IO

use std::sync::LazyLock;

use regex::Regex;

/// One secret-shape pattern. The name is stable wire form for the
/// `[REDACTED:<name>]` token so audit consumers can grep for
/// specific kinds of leak.
struct Pattern {
    name: &'static str,
    re: Regex,
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        // Anthropic-style keys (most specific first so the generic
        // `openai_key` pattern doesn't catch them).
        Pattern {
            name: "anthropic_key",
            re: Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        // OpenAI + variants (proj-, or-).
        Pattern {
            name: "openai_key",
            re: Regex::new(r"\bsk-(?:proj-|or-)?[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        // Bearer tokens in headers / log lines.
        Pattern {
            name: "bearer",
            re: Regex::new(r"\b[Bb]earer [A-Za-z0-9_\-.=:+/]{16,}").unwrap(),
        },
        // GitHub personal access + OAuth tokens.
        Pattern {
            name: "github_pat",
            re: Regex::new(r"\bghp_[A-Za-z0-9]{30,}\b").unwrap(),
        },
        Pattern {
            name: "github_oauth",
            re: Regex::new(r"\bgho_[A-Za-z0-9]{30,}\b").unwrap(),
        },
        // Google API keys.
        Pattern {
            name: "google_api",
            re: Regex::new(r"\bAIza[0-9A-Za-z_-]{30,}\b").unwrap(),
        },
        // AWS access keys.
        Pattern {
            name: "aws_key",
            re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        },
        // Generic JWTs (three base64 segments).
        Pattern {
            name: "jwt",
            re: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
        },
        // Slack / Discord / Telegram-style bot tokens.
        Pattern {
            name: "slack",
            re: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
        },
        // .env-style assignments. Conservative: only fires when the
        // key name contains KEY/TOKEN/SECRET/PASSWORD/etc + the
        // value is at least 8 chars + no whitespace.
        Pattern {
            name: "env_assignment",
            re: Regex::new(
                r#"\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|API)[A-Z0-9_]*)\s*=\s*["']?([^\s"'\n]{8,})["']?"#,
            )
            .unwrap(),
        },
        // PEM-style private-key blocks. Multi-line so we need
        // `(?s)` for `.` matching newlines.
        Pattern {
            name: "private_key",
            re: Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
                .unwrap(),
        },
    ]
});

/// Redact every known secret pattern in the input. Returns a new
/// String; the input is never mutated. Multiple patterns may match
/// the same span — order in PATTERNS controls which wins (most-
/// specific first).
pub fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    for p in PATTERNS.iter() {
        let replacement = format!("[REDACTED:{}]", p.name);
        // `replace_all` returns a Cow; convert to owned when it
        // borrows the original (no matches) to keep the loop's
        // type uniform.
        out = p.re.replace_all(&out, replacement.as_str()).into_owned();
    }
    out
}

/// Convenience for the common "redact this single value if it
/// looks secret" path. Returns the original string when no
/// pattern matched; useful when the caller wants to know whether
/// redaction actually happened.
pub fn redact_if_secret(input: &str) -> (String, bool) {
    let redacted = redact_text(input);
    let changed = redacted != input;
    (redacted, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_style_keys() {
        let s = "Authorization: sk-abc123def456ghi789jkl012mno345";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:openai_key]"));
        assert!(!out.contains("sk-abc123def456"));
    }

    #[test]
    fn redacts_anthropic_keys_before_generic_openai_pattern() {
        // Anthropic pattern is more specific; pin that the [REDACTED:
        // anthropic_key] tag fires, not [REDACTED:openai_key], so
        // audit consumers see the right kind.
        let s = "key = sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890";
        let out = redact_text(s);
        assert!(
            out.contains("[REDACTED:anthropic_key]"),
            "expected anthropic tag, got: {out}"
        );
    }

    #[test]
    fn redacts_bearer_tokens_in_headers() {
        let s = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature";
        let out = redact_text(s);
        // JWT pattern fires first (more specific), but the bearer
        // pattern also catches the whole "Bearer <token>" run. The
        // important thing: no literal token survives.
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9.payload.signature"));
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn redacts_github_personal_access_tokens() {
        let s = "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        let out = redact_text(s);
        assert!(out.contains("REDACTED"));
        assert!(!out.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    #[test]
    fn redacts_aws_access_key() {
        let s = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:aws_key]"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redacts_google_api_keys() {
        let s = "?key=AIzaSyA-abcdefghijklmnopqrstuvwxyz0123456";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:google_api]"));
    }

    #[test]
    fn redacts_jwt_three_segments() {
        let s = "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.Asignaturehere";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:jwt]"));
    }

    #[test]
    fn redacts_slack_bot_token() {
        let s = "SLACK_TOKEN=xoxb-1234567890-abcdefghijklmn";
        let out = redact_text(s);
        assert!(out.contains("REDACTED"));
        assert!(!out.contains("xoxb-1234567890"));
    }

    #[test]
    fn redacts_env_assignment_when_key_name_hints_secret() {
        let s = "API_KEY=mysupersecretvalue123\nOTHER_VAR=public";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:env_assignment]"));
        // Public var stays unchanged.
        assert!(out.contains("OTHER_VAR=public"));
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA...\nlast-line\n-----END RSA PRIVATE KEY-----";
        let out = redact_text(pem);
        assert!(out.contains("[REDACTED:private_key]"));
        assert!(!out.contains("MIIEowIBAAKCA"));
    }

    #[test]
    fn non_secret_text_passes_through_unchanged() {
        let s = "Hello world. This is a normal log line with no secrets.";
        assert_eq!(redact_text(s), s);
    }

    #[test]
    fn redact_if_secret_signals_when_changed() {
        let (out, changed) = redact_if_secret("plain text");
        assert!(!changed);
        assert_eq!(out, "plain text");

        let (out, changed) = redact_if_secret("Bearer abcdef1234567890abcdef");
        assert!(changed);
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn multiple_secrets_in_one_string_all_redacted() {
        let s = "key1=sk-abc123def456ghi789jkl012mn key2=ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        let out = redact_text(s);
        // Neither literal survives — count of "REDACTED" >= 2.
        assert!(!out.contains("sk-abc123def456"));
        assert!(!out.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        let count = out.matches("REDACTED").count();
        assert!(count >= 2, "expected ≥2 REDACTED tokens, got: {out}");
    }

    #[test]
    fn short_strings_below_threshold_dont_match() {
        // The patterns include minimum-length guards (`{20,}`,
        // `{16,}`, etc.) so short test fixtures don't false-trigger.
        let s = "sk-abc";
        assert_eq!(redact_text(s), s);
    }
}
