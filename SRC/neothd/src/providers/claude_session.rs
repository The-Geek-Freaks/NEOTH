//! B-6 Item 3g — claude-cli session UUID validation + dead-JSONL
//! `--resume` strip.
//!
//! claude-cli stores its conversation history as
//! `~/.claude/sessions/<uuid>.jsonl`. The CLI accepts `--session-id
//! <uuid>` or `--resume <uuid>` to resume a prior conversation. Two
//! bug patterns this module guards against:
//!
//!   1. **Bad UUID format slips into CLI args.** Operator typos or
//!      truncated copy-paste send a non-UUID string into
//!      `--session-id`; the CLI silently creates a *new* session
//!      named with the garbage text, splitting the operator's
//!      conversation history. `validate_session_uuid(s)` returns
//!      `false` for anything that is not canonical RFC 4122 8-4-4-4-12
//!      hex form so callers reject early.
//!
//!   2. **`--resume <uuid>` of a deleted JSONL.** Operator restarted
//!      their machine + their freedom.yaml carries a stale
//!      `last_session_id` that no longer exists on disk. claude-cli
//!      surfaces this as a cryptic "session not found" pane state
//!      that the warm-session protocol can't recover from.
//!      `strip_dead_resume_args(args, dir)` walks the operator's args
//!      and drops the `--resume`/`--session-id` flag + its value when
//!      the corresponding `<dir>/<uuid>.jsonl` is missing.
//!
//! Both functions are pure — no IO inside `validate_session_uuid`, a
//! single `Path::exists` per resume flag in `strip_dead_resume_args`.
//! Tested via temp-dir fixtures so we don't depend on the operator's
//! real `~/.claude/sessions` layout.

use std::path::{Path, PathBuf};

/// Resolve the directory where claude-cli stores session JSONLs.
/// Uses `HOME` (Unix) or `USERPROFILE` (Windows), then appends
/// `.claude/sessions`. Returns `None` when no home dir is available.
pub fn claude_sessions_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".claude").join("sessions"))
}

/// True ⇔ `s` matches the canonical RFC 4122 UUID form:
/// 8-4-4-4-12 lower/upper hex with single ASCII dashes at the
/// expected positions. Does NOT validate the variant or version
/// nibbles — claude-cli accepts any v4-shaped UUID without checking
/// the version bits, so a strict v4 gate would over-reject.
pub fn validate_session_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let is_dash_slot = i == 8 || i == 13 || i == 18 || i == 23;
        if is_dash_slot {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// CLI flag names claude-cli accepts to resume a session. Pinned
/// constants so a drift-guard test catches an upstream rename.
pub const RESUME_FLAG_LONG: &str = "--resume";
pub const SESSION_ID_FLAG_LONG: &str = "--session-id";

/// Strip `--resume <uuid>` + `--session-id <uuid>` pairs from `args`
/// when the corresponding `<sessions_dir>/<uuid>.jsonl` is missing.
/// Returns a fresh `Vec<String>` (immutable-first per the project's
/// coding-style hard rule).
///
/// Behaviour matrix:
///   - Flag with valid UUID + live JSONL    → keep both tokens.
///   - Flag with valid UUID + missing JSONL → drop both tokens
///     (operator wanted resume but the file is gone).
///   - Flag with INVALID UUID format        → drop both tokens
///     (a typo in `--resume` is never a thing claude-cli can do
///     anything useful with).
///   - Flag without a following value       → drop the lone flag.
///   - Unrelated args                        → passed through verbatim.
pub fn strip_dead_resume_args(args: &[String], sessions_dir: &Path) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == RESUME_FLAG_LONG || a == SESSION_ID_FLAG_LONG {
            let next = args.get(i + 1);
            match next {
                Some(uuid) if validate_session_uuid(uuid) => {
                    let jsonl = sessions_dir.join(format!("{uuid}.jsonl"));
                    if jsonl.exists() {
                        out.push(a.clone());
                        out.push(uuid.clone());
                    }
                    // skip both tokens (drop) when JSONL missing.
                    i += 2;
                    continue;
                }
                Some(_) => {
                    // bad UUID format → drop both tokens.
                    i += 2;
                    continue;
                }
                None => {
                    // dangling flag → drop the lone token.
                    i += 1;
                    continue;
                }
            }
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_session(dir: &Path, uuid: &str) {
        fs::write(dir.join(format!("{uuid}.jsonl")), b"{}\n").unwrap();
    }

    // ── UUID format validation ──────────────────────────────────

    #[test]
    fn validate_accepts_canonical_lowercase_uuid() {
        assert!(validate_session_uuid(
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
        ));
    }

    #[test]
    fn validate_accepts_canonical_uppercase_uuid() {
        assert!(validate_session_uuid(
            "1B4E28BA-2FA1-11D2-883F-0016D3CCA427"
        ));
    }

    #[test]
    fn validate_accepts_mixed_case_uuid() {
        assert!(validate_session_uuid(
            "1b4e28BA-2fa1-11D2-883f-0016D3cca427"
        ));
    }

    #[test]
    fn validate_rejects_wrong_length() {
        assert!(!validate_session_uuid(""));
        assert!(!validate_session_uuid("too-short"));
        assert!(!validate_session_uuid(
            "1b4e28ba-2fa1-11d2-883f-0016d3cca42700"
        ));
    }

    #[test]
    fn validate_rejects_missing_dashes() {
        assert!(!validate_session_uuid(
            "1b4e28ba2fa111d2883f0016d3cca427000"
        ));
    }

    #[test]
    fn validate_rejects_non_hex_chars() {
        assert!(!validate_session_uuid(
            "1b4e28ba-2fa1-11d2-883f-0016d3cca42g"
        ));
        assert!(!validate_session_uuid(
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ));
    }

    #[test]
    fn validate_rejects_dashes_at_wrong_positions() {
        // 9 chars before first dash (off by one).
        assert!(!validate_session_uuid(
            "1b4e28ba2-fa1-11d2-883f-0016d3cca427"
        ));
    }

    // ── strip_dead_resume_args ──────────────────────────────────

    #[test]
    fn strip_keeps_resume_args_when_jsonl_exists() {
        let dir = TempDir::new().unwrap();
        let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        write_session(dir.path(), uuid);
        let args = vec!["--resume".into(), uuid.into(), "extra".into()];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, vec!["--resume", uuid, "extra"]);
    }

    #[test]
    fn strip_drops_resume_args_when_jsonl_missing() {
        let dir = TempDir::new().unwrap();
        let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        // do NOT create the jsonl.
        let args = vec!["--resume".into(), uuid.into(), "extra".into()];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, vec!["extra"]);
    }

    #[test]
    fn strip_drops_session_id_args_when_jsonl_missing() {
        let dir = TempDir::new().unwrap();
        let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        let args = vec!["--session-id".into(), uuid.into(), "post".into()];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, vec!["post"]);
    }

    #[test]
    fn strip_drops_args_with_bad_uuid_format() {
        let dir = TempDir::new().unwrap();
        let args = vec!["--resume".into(), "not-a-uuid".into(), "tail".into()];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, vec!["tail"]);
    }

    #[test]
    fn strip_drops_dangling_resume_flag() {
        let dir = TempDir::new().unwrap();
        let args = vec!["--resume".into()];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert!(stripped.is_empty());
    }

    #[test]
    fn strip_preserves_unrelated_args() {
        let dir = TempDir::new().unwrap();
        let args = vec![
            "--model".into(),
            "opus".into(),
            "--system-prompt".into(),
            "be terse".into(),
        ];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, args);
    }

    #[test]
    fn strip_handles_multiple_resume_pairs_in_one_args_list() {
        let dir = TempDir::new().unwrap();
        let alive = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        let dead = "deadbeef-dead-beef-dead-beefdeadbeef";
        write_session(dir.path(), alive);
        let args = vec![
            "--resume".into(),
            alive.into(),
            "--session-id".into(),
            dead.into(),
            "post".into(),
        ];
        let stripped = strip_dead_resume_args(&args, dir.path());
        assert_eq!(stripped, vec!["--resume", alive, "post"]);
    }

    #[test]
    fn strip_returns_empty_for_empty_input() {
        let dir = TempDir::new().unwrap();
        let stripped = strip_dead_resume_args(&[], dir.path());
        assert!(stripped.is_empty());
    }

    #[test]
    fn flag_constants_pinned_to_canonical_long_forms() {
        // Drift guard — if upstream renames the flag, the constants
        // here need an update + a memo to refresh
        // `claude_openai_bridge.py` parity too.
        assert_eq!(RESUME_FLAG_LONG, "--resume");
        assert_eq!(SESSION_ID_FLAG_LONG, "--session-id");
    }
}
