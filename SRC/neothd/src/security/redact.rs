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
//!     Anthropic / GitHub / GitLab / npm / Google / AWS / JWT /
//!     Slack / Discord / Telegram / HTTP auth / generic credential
//!     assignments / PEM blocks)
//!   - `redact_text(input)` returns a new String with every match
//!     replaced by `[REDACTED:<kind>]`
//!   - Pure function — no IO, no allocation beyond the output
//!     String
//!   - Conservative: prefers false positives (a non-secret string
//!     that happens to look like one) over leaking a real secret
//!
//! `sanitize_tool_output` is the canonical external-text boundary used by MCP,
//! coding diagnostics, provider-derived summaries, recall/code-map egress, and
//! persistent CCR. `redact_text` remains the narrower shape-only primitive for
//! callers that have already handled terminal controls and structured data.

use std::borrow::Cow;
use std::sync::LazyLock;

use base64::Engine as _;
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
            re: Regex::new(r"(?i)\bbearer [A-Za-z0-9_\-.=:+/]{16,}").unwrap(),
        },
        // GitHub personal access + OAuth tokens.
        Pattern {
            name: "github_fine_grained_pat",
            re: Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").unwrap(),
        },
        Pattern {
            name: "github_pat",
            re: Regex::new(r"\bghp_[A-Za-z0-9]{30,}\b").unwrap(),
        },
        Pattern {
            name: "github_token",
            re: Regex::new(r"\bgh[opsru]_[A-Za-z0-9]{30,}\b").unwrap(),
        },
        Pattern {
            name: "gitlab_pat",
            re: Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        Pattern {
            name: "npm_token",
            re: Regex::new(r"\bnpm_[A-Za-z0-9]{30,}\b").unwrap(),
        },
        // Google API keys.
        Pattern {
            name: "google_api",
            re: Regex::new(r"\bAIza[0-9A-Za-z_-]{30,}\b").unwrap(),
        },
        // AWS access keys.
        Pattern {
            name: "aws_key",
            re: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        },
        // Generic JWTs (three base64 segments).
        Pattern {
            name: "jwt",
            re: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
        },
        // Chat-platform bot/session tokens. Keep these shapes separate: their
        // alphabets and lengths are different enough that one broad pattern
        // would either miss real values or redact ordinary dotted text.
        Pattern {
            name: "slack",
            re: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
        },
        Pattern {
            name: "discord_token",
            re: Regex::new(
                r"\b(?:mfa\.[A-Za-z0-9_-]{40,}|[A-Za-z0-9_-]{20,32}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,})\b",
            )
            .unwrap(),
        },
        Pattern {
            name: "telegram_bot_token",
            re: Regex::new(r"\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b").unwrap(),
        },
        // .env-style assignments. Anchor to a complete assignment line and
        // require a delimited credential component. This catches API_KEY,
        // aws_secret_access_key and DB_PASSWORD without treating ordinary
        // identifiers such as api_version or monkey as credentials.
        Pattern {
            name: "env_assignment",
            re: Regex::new(
                r#"(?im)^[ \t]*(?:export[ \t]+)?(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|private[_-]?key|secret|token|password|passwd|pwd)(?:[_-][a-z0-9]+)*[ \t]*=[ \t]*["']?([^\s"'\[\r\n][^\s"'\r\n]{7,})["']?"#,
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

/// Candidate HTTP Basic credentials. Regex shape alone is not sufficient:
/// normal prose such as `basic auth` is also syntactically valid base64 text.
/// Every candidate therefore has to decode to a printable `user:password`
/// payload before it is treated as a credential.
static BASIC_AUTH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bbasic[ \t]+(?P<token>[A-Za-z0-9+/]{4,}={0,2})").unwrap());

pub(crate) fn is_basic_auth_credential(token: &str) -> bool {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(token));
    let Ok(decoded) = decoded else {
        return false;
    };
    let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
        return false;
    };
    separator > 0
        && decoded
            .iter()
            .all(|byte| matches!(*byte, b' '..=b'~' | 0x80..=0xff))
}

fn redact_basic_auth(input: &str) -> String {
    BASIC_AUTH_RE
        .replace_all(input, |captures: &regex::Captures<'_>| {
            if is_basic_auth_credential(&captures["token"]) {
                "[REDACTED:basic_auth]".to_string()
            } else {
                captures[0].to_string()
            }
        })
        .into_owned()
}

/// ANSI escape sequences (QU-04). Tool output — `cargo`, `git`, test
/// runners — colourises by default, so a coding worker's captured
/// stdout/stderr arrives studded with `\x1b[...m` SGR codes plus the
/// occasional cursor-move (CSI) or hyperlink (OSC). Left raw they
/// land verbatim in WAL frames + the activity feed, where the escape
/// bytes are noise at best and can corrupt a naive terminal renderer
/// at worst. The alternation order is load-bearing: CSI (`\x1b[…`)
/// and OSC (`\x1b]…`) are matched before the generic two-byte escape
/// catch-all so `\x1b]` opens an OSC rather than being eaten as a
/// lone escape.
///
/// The OSC terminator is OPTIONAL (`(?:\x07|\x1b\\)?`) so an
/// UNTERMINATED OSC — a capture truncated mid-sequence at EOF, or a
/// stray `\x1b]` — is still fully consumed rather than leaving its
/// body bytes in the output. The body excludes `\n` so a stray
/// `\x1b]` can never swallow more than its own line (matches terminal
/// OSC semantics while bounding the blast radius on malformed input).
static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b\n]*(?:\x07|\x1b\\)?|[@-Z\\-_])").unwrap()
});

/// One or more consecutive `../` or `..\` path-traversal segments
/// (QU-04). A run like `../../../` collapses to a single marker so
/// the neutralised output stays readable. Bare `..` with no
/// separator is intentionally NOT matched — it's a legitimate token
/// in prose ("wait..") and in version ranges; only the directory-
/// separator-bearing form is a traversal primitive.
static PATH_TRAVERSAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\.[\\/])+").unwrap());

/// Strip every ANSI escape sequence from `input` (QU-04). Pure
/// function, borrows when there's nothing to strip. Use this on any
/// captured terminal output BEFORE it rides into a WAL frame or the
/// operator activity feed — see [`sanitize_tool_output`] for the
/// combined ANSI-then-secret pass.
pub fn strip_ansi(input: &str) -> Cow<'_, str> {
    ANSI_RE.replace_all(input, "")
}

/// Centralised tool-output sanitiser (QU-04). The single canonical
/// surface for any text-typed external IO — captured tool stdout,
/// provider error strings, plugin trap messages — on its way to a
/// durable WAL frame or the activity feed. Composes [`strip_ansi`]
/// (terminal-control noise), removal of unsafe C0/C1 controls, a detection-only
/// deobfuscation pass for zero-width token splitters, single-value JSON decoding
/// for structured tool output, sensitive-field redaction, and [`redact_text`]
/// (secret shapes).
///
/// Why ANSI first: a colourised secret (`\x1b[31msk-…\x1b[0m`) would
/// otherwise have escape bytes wedged inside the token, breaking the
/// `\b` word-boundary the secret regexes anchor on. Stripping the
/// control bytes first lets the secret patterns see a clean token.
///
/// Path-traversal neutralisation is deliberately NOT part of this
/// pass — `cargo`/`rustc` diagnostics legitimately print relative
/// paths (`--> ../src/foo.rs`) and rewriting them would corrupt the
/// audit trail. Callers that handle UNTRUSTED paths (e.g. a plugin
/// echoing an operator-supplied path into a file op) call
/// [`neutralize_path_traversal`] explicitly at that boundary.
pub fn sanitize_tool_output(input: &str) -> String {
    let no_ansi = strip_ansi(input);
    let no_controls = strip_unsafe_controls(&no_ansi);
    let deobfuscated = strip_secret_obfuscators(&no_controls);
    if matches!(&deobfuscated, Cow::Owned(_)) {
        let sanitized = sanitize_structured_and_flat(&deobfuscated);
        if sanitized != deobfuscated {
            // A known secret became visible only after removing zero-width
            // splitters. Return the safe canonical view, but never reconstitute
            // an untrusted-data guard sigil that was deliberately defanged with
            // the same zero-width character. Clean Unicode keeps the original
            // byte sequence through the fallback below.
            return defang_guard_sigils(&sanitized);
        }
    }
    sanitize_structured_and_flat(&no_controls)
}

fn sanitize_structured_and_flat(input: &str) -> String {
    // Tool APIs frequently return JSON as a text content block. Decode one
    // complete JSON value so short credentials hidden behind a sensitive key
    // (`{"token":"short"}`) and JSON escapes cannot bypass the flat regex
    // pass. Clean JSON keeps its original whitespace; only a real redaction
    // reserializes it. serde_json's built-in recursion limit bounds depth.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        let sanitized = redact_tool_output_value(&value, "");
        if sanitized != value {
            return serde_json::to_string(&sanitized)
                .expect("serde_json::Value serialization is infallible");
        }
    }
    // Logs often surround a JSON object with prose, so the whole string is not
    // valid JSON. Still redact scalar credential fields in those fragments;
    // secret-shape matching alone cannot catch a deliberately short value.
    let contextual = TOOL_OUTPUT_JSON_FIELD_RE.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}\"[REDACTED:field]\"", &caps["prefix"])
    });
    redact_text(&contextual)
}

fn strip_unsafe_controls(input: &str) -> Cow<'_, str> {
    if !input
        .chars()
        .any(|ch| ch == '\r' || (ch.is_control() && !matches!(ch, '\n' | '\t')))
    {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' if chars.peek() == Some(&'\n') => {
                chars.next();
                out.push('\n');
            }
            '\r' => {}
            '\n' | '\t' => out.push(ch),
            control if control.is_control() => {}
            other => out.push(other),
        }
    }
    Cow::Owned(out)
}

fn strip_secret_obfuscators(input: &str) -> Cow<'_, str> {
    if !input.chars().any(|ch| {
        matches!(
            ch,
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
        )
    }) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(
        input
            .chars()
            .filter(|ch| {
                !matches!(
                    ch,
                    '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
                )
            })
            .collect(),
    )
}

fn sanitize_scalar_text(input: &str) -> String {
    let no_ansi = strip_ansi(input);
    let no_controls = strip_unsafe_controls(&no_ansi);
    let deobfuscated = strip_secret_obfuscators(&no_controls);
    if matches!(&deobfuscated, Cow::Owned(_)) {
        let sanitized = sanitize_flat_text(&deobfuscated);
        if sanitized != deobfuscated {
            return defang_guard_sigils(&sanitized);
        }
    }
    sanitize_flat_text(&no_controls)
}

fn sanitize_flat_text(input: &str) -> String {
    let contextual = TOOL_OUTPUT_JSON_FIELD_RE.replace_all(input, |caps: &regex::Captures<'_>| {
        format!("{}\"[REDACTED:field]\"", &caps["prefix"])
    });
    redact_text(&contextual)
}

fn defang_guard_sigils(input: &str) -> String {
    input
        .replace("<<<", "<\u{200b}<\u{200b}<")
        .replace(">>>", ">\u{200b}>\u{200b}>")
}

/// Credential-bearing JSON keys for external tool output. Session identifiers
/// are deliberately absent: MCP/browser/database tools commonly return a
/// `session_id` handle that must survive into a follow-up call. The broader
/// [`ALWAYS_REDACT_KEYS`] policy remains available for diagnostic logging where
/// hiding identifiers is appropriate.
const TOOL_OUTPUT_REDACT_KEYS: &[&str] = &[
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
];

static TOOL_OUTPUT_JSON_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = TOOL_OUTPUT_REDACT_KEYS
        .iter()
        .map(|key| {
            key.split(['_', '-'])
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("[_-]?")
        })
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!(
        r#"(?i)(?P<prefix>"(?:{keys})"\s*:\s*)(?:"(?:\\.|[^"\\])*"|-?(?:[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)|true|false|null)"#
    ))
    .expect("static tool-output credential-field regex is valid")
});

fn redact_tool_output_value(value: &serde_json::Value, field_hint: &str) -> serde_json::Value {
    if is_tool_output_credential_key(field_hint) {
        return serde_json::Value::String("[REDACTED:field]".into());
    }
    match value {
        serde_json::Value::String(text) => {
            // JSON escapes are decoded only after the outer pass. Canonicalize
            // again at the actual string leaf so escaped ANSI, controls, or
            // zero-width splitters cannot hide a credential.
            serde_json::Value::String(sanitize_scalar_text(text))
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| redact_tool_output_value(value, ""))
                .collect(),
        ),
        serde_json::Value::Object(object) => {
            let mut out = serde_json::Map::with_capacity(object.len());
            for (key, value) in object {
                out.insert(key.clone(), redact_tool_output_value(value, key));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

fn is_tool_output_credential_key(field: &str) -> bool {
    TOOL_OUTPUT_REDACT_KEYS.iter().any(|candidate| {
        field
            .bytes()
            .filter(|byte| !matches!(*byte, b'_' | b'-'))
            .map(|byte| byte.to_ascii_lowercase())
            .eq(candidate
                .bytes()
                .filter(|byte| !matches!(*byte, b'_' | b'-'))
                .map(|byte| byte.to_ascii_lowercase()))
    })
}

/// Returns true when `input` contains at least one `../` or `..\`
/// path-traversal segment (QU-04). Cheap substring check for callers
/// that want to branch (reject vs neutralise) before paying for the
/// regex rewrite in [`neutralize_path_traversal`].
pub fn contains_path_traversal(input: &str) -> bool {
    input.contains("../") || input.contains("..\\")
}

/// Replace every run of `../` / `..\` traversal segments with a
/// single `[REDACTED:path_traversal]` marker (QU-04). Pure function,
/// borrows when there's nothing to neutralise. The marker matches
/// the module's `[REDACTED:<kind>]` convention so audit consumers can
/// grep traversal hits the same way they grep secret hits.
///
/// This is an OPT-IN boundary tool, not part of [`sanitize_tool_output`]
/// — see that function's doc for why blanket traversal-rewriting
/// would corrupt legitimate compiler-diagnostic paths.
pub fn neutralize_path_traversal(input: &str) -> Cow<'_, str> {
    PATH_TRAVERSAL_RE.replace_all(input, "[REDACTED:path_traversal]")
}

/// Redact every known secret pattern in the input. Returns a new
/// String; the input is never mutated. Multiple patterns may match
/// the same span — order in PATTERNS controls which wins (most-
/// specific first).
pub fn redact_text(input: &str) -> String {
    let mut out = redact_basic_auth(input);
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
    for captures in BASIC_AUTH_RE.captures_iter(input) {
        if !is_basic_auth_credential(&captures["token"]) {
            continue;
        }
        let Some(matched) = captures.get(0) else {
            continue;
        };
        let overlaps = hits
            .iter()
            .any(|hit| !(matched.end() <= hit.start || matched.start() >= hit.end));
        if !overlaps {
            hits.push(SecretMatch {
                kind: "basic_auth",
                start: matched.start(),
                end: matched.end(),
                text: matched.as_str().to_string(),
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

/// QU-04 deny-list: field names whose VALUE is always redacted
/// regardless of whether the value itself matches a secret-shape
/// pattern. A 4-char `api_key` value is too short to trip any
/// regex in PATTERNS, but the field name alone tells us it's
/// sensitive. Entries are lowercase; [`is_sensitive_field_name`]
/// lowercases the candidate before comparing.
pub const ALWAYS_REDACT_KEYS: &[&str] = &[
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

/// Case-insensitive field-name match against [`ALWAYS_REDACT_KEYS`],
/// the standard set of secret-bearing keys. Public for callers that
/// want the same rule applied to a single field check outside the
/// recursive walker.
pub fn is_sensitive_field_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ALWAYS_REDACT_KEYS.iter().any(|s| lower == *s)
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
    fn lf_p1_03_redacts_modern_repository_and_registry_tokens() {
        let fixtures = [
            concat!("github_", "pat_FAKE_TEST_AAAAAAAAAAAAAAAAAAAAAAAA"),
            concat!("ghs", "_FAKETOKENFORTESTONLYAAAAAAAAAAAAA"),
            concat!("glpat", "-FAKE_TEST_AAAAAAAAAAAAAAAAAAAAA"),
            concat!("npm", "_FAKETOKENFORTESTONLYAAAAAAAAAAAAAAA"),
        ];
        for fixture in fixtures {
            let out = redact_text(&format!("credential={fixture}"));
            assert!(!out.contains(fixture), "token survived: {out}");
            assert!(out.contains("REDACTED"), "marker missing: {out}");
        }
    }

    #[test]
    fn lf_p1_03_redacts_chat_platform_and_basic_auth_tokens() {
        let fixtures = [
            concat!("mfa.", "FAKE_TEST_DISCORD_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            concat!("123456789:", "FAKE_TEST_TELEGRAM_AAAAAAAAAAAAAAAAAAAAA"),
            concat!("Basic ", "ZmFrZS11c2Vy", "OmZha2UtcGFzcw=="),
            "BASIC YTpi",
            concat!("BEARER ", "FAKE_TEST_BEARER_AAAAAAAAAAAAAAAAA"),
        ];
        for fixture in fixtures {
            let out = redact_text(&format!("Authorization: {fixture}"));
            assert!(!out.contains(fixture), "token survived: {out}");
            assert!(out.contains("REDACTED"), "marker missing: {out}");
        }
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
        let s = "API_KEY=mysupersecretvalue123\naws_secret_access_key=lowercase_secret_value\nOTHER_VAR=public";
        let out = redact_text(s);
        assert!(out.contains("[REDACTED:env_assignment]"));
        assert!(!out.contains("lowercase_secret_value"));
        // Public var stays unchanged.
        assert!(out.contains("OTHER_VAR=public"));
    }

    #[test]
    fn lf_p1_03_basic_prose_and_noncredential_identifiers_are_not_redacted() {
        let input = "basic auth\nbasic test\napi_version = \"2024-01-01\"\nmonkey = \"abcdefgh\"";
        assert_eq!(redact_text(input), input);
        assert_eq!(sanitize_tool_output(input), input);
        assert!(find_secret_kinds(input).is_empty());
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
                "name": "sam",
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
        assert_eq!(out["user"]["name"], "sam");
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

    // ── QU-04 (Session 28b) strip_ansi / sanitize_tool_output ─────────

    #[test]
    fn qu_04_strip_ansi_removes_sgr_colour_codes() {
        let s = "\x1b[31mERROR\x1b[0m: build failed";
        assert_eq!(strip_ansi(s), "ERROR: build failed");
    }

    #[test]
    fn qu_04_strip_ansi_removes_csi_cursor_moves() {
        // CSI cursor-up (`\x1b[2A`) + clear-line (`\x1b[K`) — common in
        // progress-bar tool output.
        let s = "line1\x1b[2A\x1b[Kline2";
        assert_eq!(strip_ansi(s), "line1line2");
    }

    #[test]
    fn qu_04_strip_ansi_removes_osc_hyperlink() {
        // OSC 8 hyperlink terminated by BEL (`\x07`) — modern cargo
        // emits these for clickable error codes.
        let s = "see \x1b]8;;https://example.com\x07E0425\x1b]8;;\x07 here";
        assert_eq!(strip_ansi(s), "see E0425 here");
    }

    #[test]
    fn qu_04_strip_ansi_consumes_unterminated_osc() {
        // ANSI-OSC-1 (review fix): a capture truncated mid-OSC at EOF
        // (no BEL/ST terminator) must still be fully stripped, not leave
        // its body bytes behind.
        let s = "prefix \x1b]0;truncated-title";
        assert_eq!(strip_ansi(s), "prefix ");
    }

    #[test]
    fn qu_04_strip_ansi_unterminated_osc_bounded_at_newline() {
        // A stray `\x1b]` must not swallow more than its own line — the
        // OSC body excludes `\n`, so the following line survives intact.
        let s = "\x1b]0;stray-osc\nreal content line";
        assert_eq!(strip_ansi(s), "\nreal content line");
    }

    #[test]
    fn qu_04_sanitize_tool_output_drops_secret_hidden_in_unterminated_osc() {
        // A secret smuggled into an (unterminated) OSC title is terminal
        // metadata, not content — strip_ansi removes the whole sequence,
        // so the secret never reaches the output at all.
        let fixture = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        let s = format!("log \x1b]0;{fixture}");
        let out = sanitize_tool_output(&s);
        assert!(!out.contains(fixture), "secret survived: {out:?}");
        assert!(!out.contains('\x1b'), "escape bytes survived: {out:?}");
    }

    #[test]
    fn qu_04_strip_ansi_borrows_when_no_escapes() {
        // Pure passthrough must not allocate — assert we got the
        // Borrowed variant back, not an owned copy.
        let s = "plain text, no escapes";
        match strip_ansi(s) {
            Cow::Borrowed(b) => assert_eq!(b, s),
            Cow::Owned(_) => panic!("expected Borrowed for escape-free input"),
        }
    }

    #[test]
    fn qu_04_sanitize_tool_output_strips_ansi_then_redacts_secret() {
        // A colourised secret: the SGR codes sit INSIDE the token, so
        // a raw `redact_text` would miss it (the `\b` boundary breaks
        // on `\x1b`). sanitize_tool_output strips ANSI first.
        let fixture = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        let s = format!("key: \x1b[33m{fixture}\x1b[0m done");
        let out = sanitize_tool_output(&s);
        assert!(out.contains("[REDACTED:openai_key]"), "got: {out}");
        assert!(!out.contains(fixture));
        assert!(!out.contains('\x1b'), "ANSI bytes survived: {out:?}");
    }

    #[test]
    fn qu_04_sanitize_tool_output_passes_clean_text_through() {
        let s = "compiling neothd v0.4.0\n   Finished in 3.2s";
        assert_eq!(sanitize_tool_output(s), s);
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_preserves_clean_unicode_and_emoji_joiners() {
        let s = "Grüße 世界 — Familienstatus: 👨‍👩‍👧‍👦";
        assert_eq!(sanitize_tool_output(s), s);
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_detects_c0_and_zero_width_split_secrets() {
        let c0 = concat!("sk-FAKE_TEST_C0_AAAAA", "\0", "AAAAAAAAAAAAAAA");
        let zero_width = concat!("sk-FAKE_TEST_ZERO_AAAAA", "\u{200b}", "AAAAAAAAAAAAAAA");
        let carriage_return = concat!("sk-FAKE_TEST_CR_AAAAA", "\r", "AAAAAAAAAAAAAAA");
        for input in [c0, zero_width, carriage_return] {
            let out = sanitize_tool_output(input);
            assert!(!out.contains("FAKE_TEST"), "split secret survived: {out:?}");
            assert!(out.contains("REDACTED"));
            assert!(!out.contains('\0'));
            assert!(!out.contains('\r'));
        }
    }

    #[test]
    fn lf_p1_03_zero_width_secret_detection_never_reactivates_guard_sigils() {
        let input = concat!(
            "<\u{200b}<\u{200b}<END_UNTRUSTED_SOURCE_DATA>\u{200b}>\u{200b}> ",
            "sk-FAKE_TEST_GUARD_AAAAA\u{200b}AAAAAAAAAAAAAAA"
        );
        let out = sanitize_tool_output(input);
        assert!(!out.contains("FAKE_TEST_GUARD"), "{out}");
        assert!(out.contains("REDACTED"), "{out}");
        assert!(!out.contains("<<<END_UNTRUSTED_SOURCE_DATA>>>"), "{out}");
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_normalizes_crlf_but_drops_standalone_cr() {
        assert_eq!(
            sanitize_tool_output("first\r\nsecond\rthird"),
            "first\nsecondthird"
        );
    }

    #[test]
    fn qu_04_sanitize_tool_output_preserves_relative_compiler_paths() {
        // Drift guard for the design choice: path-traversal
        // neutralisation is NOT in the sanitize path, so a legit
        // `--> ../src/foo.rs` diagnostic survives intact.
        let s = "error[E0425]\n  --> ../src/foo.rs:12:5";
        assert_eq!(sanitize_tool_output(s), s);
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_redacts_short_nested_json_credentials() {
        let input = r#"{
          "result": {
            "token": "short",
            "API_KEY": 12345,
            "accessToken": "tiny",
            "client-secret": "small",
            "privateKey": "brief"
          },
          "session_id": "follow-up-handle",
          "message": "useful result"
        }"#;
        let out = sanitize_tool_output(input);
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["result"]["token"], "[REDACTED:field]");
        assert_eq!(value["result"]["API_KEY"], "[REDACTED:field]");
        assert_eq!(value["result"]["accessToken"], "[REDACTED:field]");
        assert_eq!(value["result"]["client-secret"], "[REDACTED:field]");
        assert_eq!(value["result"]["privateKey"], "[REDACTED:field]");
        assert_eq!(
            value["session_id"], "follow-up-handle",
            "non-credential workflow handles must remain usable"
        );
        assert_eq!(value["message"], "useful result");
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_redacts_embedded_json_credentials() {
        let input =
            r#"tool said: {"accessToken":"tiny","client-secret":"small","ok":true} and continued"#;
        let out = sanitize_tool_output(input);
        assert!(!out.contains("tiny"), "embedded field survived: {out}");
        assert!(!out.contains("small"), "embedded field survived: {out}");
        assert!(out.contains(r#""accessToken":"[REDACTED:field]""#));
        assert!(out.contains(r#""client-secret":"[REDACTED:field]""#));
        assert!(out.contains("and continued"));
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_decodes_json_escapes_before_matching() {
        let input = r#"{"value":"sk-\u0046AKE_TEST_JSON_AAAAAAAAAAAAAAAAAAA"}"#;
        let out = sanitize_tool_output(input);
        assert!(
            !out.contains("FAKE_TEST_JSON"),
            "escaped secret survived: {out}"
        );
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_strips_json_escaped_ansi_before_matching() {
        let input = r#"{"note":"\u001b[31msk-FAKE_TEST_JSON_ANSI_AAAAAAAAAAAAAAA\u001b[0m"}"#;
        let out = sanitize_tool_output(input);
        assert!(
            !out.contains("FAKE_TEST_JSON_ANSI"),
            "escaped ANSI bypassed redaction: {out}"
        );
        assert!(!out.contains("\\u001b"), "escaped ANSI survived: {out}");
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_detects_json_escaped_zero_width_split() {
        let input = r#"{"note":"sk-FAKE_TEST_JSON_ZERO_AAAAA\u200bAAAAAAAAAAAAAAA"}"#;
        let out = sanitize_tool_output(input);
        assert!(
            !out.contains("FAKE_TEST_JSON_ZERO"),
            "escaped split survived: {out}"
        );
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn lf_p1_03_sanitize_tool_output_is_idempotent_after_structured_redaction() {
        let once = sanitize_tool_output(r#"{"token":"tiny","ok":true}"#);
        let twice = sanitize_tool_output(&once);
        assert_eq!(twice, once);
    }

    // ── QU-04 path-traversal helpers ──────────────────────────────────

    #[test]
    fn qu_04_contains_path_traversal_detects_both_separators() {
        assert!(contains_path_traversal("../etc/passwd"));
        assert!(contains_path_traversal("..\\windows\\system32"));
        assert!(contains_path_traversal("a/b/../../c"));
    }

    #[test]
    fn qu_04_contains_path_traversal_false_for_clean_and_bare_dots() {
        assert!(!contains_path_traversal("src/main.rs"));
        // Bare ".." with no separator is prose / a version token, not
        // a traversal primitive.
        assert!(!contains_path_traversal("wait.. what"));
        assert!(!contains_path_traversal("1.0..2.0"));
    }

    #[test]
    fn qu_04_neutralize_path_traversal_collapses_run_to_single_marker() {
        let out = neutralize_path_traversal("../../../etc/passwd");
        assert_eq!(out, "[REDACTED:path_traversal]etc/passwd");
    }

    #[test]
    fn qu_04_neutralize_path_traversal_handles_backslash() {
        let out = neutralize_path_traversal("..\\..\\secret.txt");
        assert_eq!(out, "[REDACTED:path_traversal]secret.txt");
    }

    #[test]
    fn qu_04_neutralize_path_traversal_borrows_when_clean() {
        let s = "src/main.rs has no traversal";
        match neutralize_path_traversal(s) {
            Cow::Borrowed(b) => assert_eq!(b, s),
            Cow::Owned(_) => panic!("expected Borrowed for traversal-free input"),
        }
    }

    #[test]
    fn qu_04_always_redact_keys_is_lowercase_and_drives_field_guard() {
        assert!(ALWAYS_REDACT_KEYS.contains(&"token"));
        for k in ALWAYS_REDACT_KEYS {
            assert_eq!(
                *k,
                k.to_ascii_lowercase(),
                "deny-list entries must be lowercase: {k}"
            );
            // Every deny-list entry must be recognised by the public
            // guard (pins the const ↔ function wiring).
            assert!(is_sensitive_field_name(k), "guard missed deny-list key {k}");
        }
    }
}
