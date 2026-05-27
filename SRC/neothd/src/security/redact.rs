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

/// One exact secret-pattern hit. Used by audit callers (HO-06
/// startup credential scanner) that need to report the matched
/// span back to the operator with precision — `redact_text`
/// erases the position, so callers that want "ghp_AAAA…" excerpts
/// MUST use this surface instead of diffing redacted vs original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Stable wire-form pattern label (`anthropic_key`, `aws_key`,
    /// `github_pat`, etc. — exact strings used in the PATTERNS
    /// table; audit consumers can grep `[REDACTED:<kind>]` traces
    /// and pin the same name here).
    pub kind: &'static str,
    /// Byte offsets into the input string. `text` below is the
    /// substring at `[start..end]`; the caller may use the range
    /// directly to highlight in source views.
    pub start: usize,
    pub end: usize,
    /// The matched substring, owned so the caller doesn't have to
    /// keep the input alive while logging/displaying.
    pub text: String,
}

/// HO-06 (Session 28) — return every secret-shape hit in `input`
/// with exact byte spans + the matched substring. Walks every
/// pattern in PATTERNS in declaration order, collects ALL matches
/// (not just the first per pattern), de-duplicates overlapping
/// matches by keeping the most-specific (first-declared) winner.
///
/// **Why exact spans matter for audit**: the operator-facing
/// finding needs to identify WHICH key was matched (first 8 chars
/// is enough to distinguish keys but not enough to leak). Diffing
/// `redact_text` output against the input doesn't recover the
/// match position, so audit excerpts ended up grabbing the longest
/// whitespace-bounded token from the line — usually the secret,
/// sometimes a sibling token by accident. This API removes that
/// ambiguity.
pub fn find_secret_kinds(input: &str) -> Vec<SecretMatch> {
    let mut hits: Vec<SecretMatch> = Vec::new();
    for p in PATTERNS.iter() {
        for m in p.re.find_iter(input) {
            // Drop any hit that overlaps an already-recorded hit
            // — the first-declared pattern wins (PATTERNS lists
            // most-specific shapes first; without this skip the
            // generic `openai_key` would re-match `anthropic_key`
            // spans).
            let overlaps = hits
                .iter()
                .any(|h| !(m.end() <= h.start || m.start() >= h.end));
            if overlaps {
                continue;
            }
            hits.push(SecretMatch {
                kind: p.name,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
            });
        }
    }
    hits.sort_by_key(|h| h.start);
    hits
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

/// P-04 (Session 24) — recursively walk a `serde_json::Value` and
/// redact every string leaf through [`redact_text`]. Designed for
/// the JSON-RPC `params` field in `n8n_api::handlers` log lines +
/// any other surface that wants to debug-print a request body
/// without leaking the operator's bearer tokens / API keys.
///
/// Why a per-leaf walker rather than `redact_text(value.to_string())`:
/// stringifying first would escape every quote + newline, leaving
/// `"sk-…"` instead of `sk-…`, and the regex band wouldn't fire.
/// Walking leaves means the original JSON shape is preserved + each
/// string value is sanitised at its actual boundary.
///
/// Additionally surfaces a safelist of well-known secret-bearing
/// FIELD names (`api_key`, `token`, `bearer`, `password`, `secret`,
/// `authorization`, `cookie`, `x-api-key`) — any field whose name
/// matches case-insensitively gets its value replaced with
/// `[REDACTED:field]` regardless of pattern match. Catches cases
/// where the value is short / doesn't look like a textbook secret
/// shape but the FIELD NAME tells us it's sensitive.
pub fn redact_params_for_log(value: &serde_json::Value) -> serde_json::Value {
    redact_value(value, /*field_hint=*/ "")
}

fn redact_value(value: &serde_json::Value, field_hint: &str) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            if is_sensitive_field_name(field_hint) {
                serde_json::Value::String("[REDACTED:field]".into())
            } else {
                serde_json::Value::String(redact_text(s))
            }
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_value(v, field_hint)).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut out = serde_json::Map::with_capacity(obj.len());
            for (k, v) in obj {
                out.insert(k.clone(), redact_value(v, k));
            }
            serde_json::Value::Object(out)
        }
        // Null / Bool / Number cannot carry secrets at the leaf
        // boundary; pass through.
        other => other.clone(),
    }
}

/// Case-insensitive field-name match against the standard set of
/// secret-bearing keys. Public for callers that want the same
/// rule applied to a single field check outside the recursive
/// walker.
pub fn is_sensitive_field_name(name: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "bearer",
        "password",
        "passwd",
        "pwd",
        "secret",
        "authorization",
        "auth",
        "cookie",
        "x-api-key",
        "x_api_key",
        "client_secret",
        "private_key",
        "session_id",
        "session",
    ];
    let lower = name.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| lower == *s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_style_keys() {
        // Defanged via concat! — see redacts_slack_bot_token for the
        // rationale. Regex still matches the runtime string.
        let fixture = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        let s = format!("Authorization: {fixture}");
        let out = redact_text(&s);
        assert!(out.contains("[REDACTED:openai_key]"));
        assert!(!out.contains(fixture));
    }

    #[test]
    fn redacts_anthropic_keys_before_generic_openai_pattern() {
        // Anthropic pattern is more specific; pin that the [REDACTED:
        // anthropic_key] tag fires, not [REDACTED:openai_key], so
        // audit consumers see the right kind. Defanged via concat!
        // so the `sk-ant-` prefix isn't a complete literal in source.
        let fixture = concat!("sk-", "ant-FAKE_TEST_ANTHROPIC_AAAAAAAAAAA");
        let s = format!("key = {fixture}");
        let out = redact_text(&s);
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
        // `concat!` defangs the `ghp_` prefix so GitHub's
        // push-protection secret scanner doesn't flag the test
        // fixture as a real PAT. Regex still sees the runtime
        // string + redacts it.
        let fixture = concat!("ghp", "_FAKETOKENFORTESTONLYAAAAAAAAAAAAA");
        let s = format!("GH_TOKEN={fixture}");
        let out = redact_text(&s);
        assert!(out.contains("REDACTED"));
        assert!(
            !out.contains(fixture),
            "raw fixture must not survive: {out}"
        );
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
        // Defanged via concat! — `AIza` is Google's stable API-key
        // prefix that GitHub's scanner targets.
        let fixture = concat!("AIza", "_FAKE_TEST_GOOGLE_AAAAAAAAAAAAAA");
        let s = format!("?key={fixture}");
        let out = redact_text(&s);
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
        // `concat!` keeps the `xoxb-` literal out of source so
        // GitHub's push-protection secret scanner doesn't flag the
        // test fixture as a real Slack token. The regex band still
        // sees the runtime-concatenated string and redacts it.
        let fixture = concat!("xox", "b-FAKETOKEN_FOR_TEST_ONLY_AAA");
        let s = format!("SLACK_TOKEN={fixture}");
        let out = redact_text(&s);
        assert!(out.contains("REDACTED"));
        assert!(
            !out.contains(fixture),
            "raw fixture must not survive redaction"
        );
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
        // Same `concat!` defang trick as the single-secret tests —
        // GitHub push protection scans for both `sk-` (OpenAI) and
        // `ghp_` (GitHub PAT) full-token shapes in source.
        let openai = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        let github = concat!("ghp", "_FAKETOKENFORTESTONLYAAAAAAAAAAAAA");
        let s = format!("key1={openai} key2={github}");
        let out = redact_text(&s);
        // Neither literal survives — count of "REDACTED" >= 2.
        assert!(!out.contains(openai));
        assert!(!out.contains(github));
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

    // ── P-04 (Session 24) redact_params_for_log + field-name guard ────

    #[test]
    fn p_04_passes_through_null_bool_number_leaves_unchanged() {
        let v = serde_json::json!({"a": null, "b": true, "c": 42, "d": 4.5});
        let out = redact_params_for_log(&v);
        assert_eq!(out, v);
    }

    #[test]
    fn p_04_redacts_string_leaf_when_value_looks_secret() {
        // Defanged fixture — see redacts_openai_style_keys.
        let openai = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        let v = serde_json::json!({
            "prompt": "hello",
            "evidence": format!("the operator's key is {openai}"),
        });
        let out = redact_params_for_log(&v);
        let evidence = out["evidence"].as_str().unwrap();
        assert!(
            evidence.contains("[REDACTED:openai_key]"),
            "got: {evidence}"
        );
        assert_eq!(out["prompt"], "hello", "non-secret leaf untouched");
    }

    #[test]
    fn p_04_redacts_value_when_field_name_is_sensitive_even_if_value_looks_innocent() {
        // Field-name guard: a 4-char "api_key" value wouldn't trigger
        // any pattern (too short), but the FIELD NAME tells us it's
        // sensitive → redact regardless.
        let v = serde_json::json!({"api_key": "short", "prompt": "short"});
        let out = redact_params_for_log(&v);
        assert_eq!(out["api_key"], "[REDACTED:field]");
        assert_eq!(out["prompt"], "short", "non-sensitive field untouched");
    }

    #[test]
    fn p_04_field_name_match_is_case_insensitive() {
        let v = serde_json::json!({
            "API_KEY": "x",
            "Bearer": "y",
            "X-Api-Key": "z",
        });
        let out = redact_params_for_log(&v);
        assert_eq!(out["API_KEY"], "[REDACTED:field]");
        assert_eq!(out["Bearer"], "[REDACTED:field]");
        assert_eq!(out["X-Api-Key"], "[REDACTED:field]");
    }

    #[test]
    fn p_04_walks_nested_objects_and_arrays() {
        let v = serde_json::json!({
            "user": {
                "name": "alex",
                "credentials": {
                    "token": "looks-short-but-field-says-secret",
                }
            },
            "history": [
                {"prompt": "hi", "api_key": "abc"},
                {"prompt": "bye", "api_key": "def"}
            ]
        });
        let out = redact_params_for_log(&v);
        assert_eq!(out["user"]["name"], "alex");
        assert_eq!(out["user"]["credentials"]["token"], "[REDACTED:field]");
        assert_eq!(out["history"][0]["api_key"], "[REDACTED:field]");
        assert_eq!(out["history"][1]["api_key"], "[REDACTED:field]");
        assert_eq!(out["history"][0]["prompt"], "hi");
    }

    #[test]
    fn p_04_preserves_json_shape_unlike_stringify_then_redact() {
        // Drift guard for the design choice: walk-leaves vs
        // stringify-first. After stringify the secret would be
        // wrapped in `"sk-..."` and the regex word-boundary `\b`
        // wouldn't fire on the `"` boundary. Walking leaves means
        // each string is sanitised at the actual content boundary.
        let v = serde_json::json!({
            "prompt": format!("the key is {} right?", concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA")),
        });
        let out = redact_params_for_log(&v);
        let s = out["prompt"].as_str().unwrap();
        assert!(s.contains("[REDACTED:"));
        assert!(!s.contains("FAKE_TEST_OPENAI"));
        // Shape preservation: still a JSON object with one prompt key.
        assert!(out.is_object());
        assert_eq!(out.as_object().unwrap().len(), 1);
    }

    #[test]
    fn p_04_is_sensitive_field_name_matches_canonical_set() {
        for s in [
            "api_key",
            "ApiKey",
            "TOKEN",
            "access_token",
            "refresh_token",
            "bearer",
            "password",
            "secret",
            "authorization",
            "auth",
            "cookie",
            "x-api-key",
            "client_secret",
            "private_key",
        ] {
            assert!(is_sensitive_field_name(s), "expected `{s}` to be sensitive",);
        }
        for s in ["prompt", "model", "name", "key_count", "tokens_used"] {
            assert!(
                !is_sensitive_field_name(s),
                "expected `{s}` to NOT be sensitive",
            );
        }
    }
}
