//! GOLD-HR-07 — tag/fence protection: never corrupt structural boundaries.
//!
//! LLM tool output carries structure a downstream parser depends on: fenced
//! code blocks (```` ``` ````), tool-call / function-call markers
//! (`<tool_call>`, `<function_calls>`, `<invoke>`), reasoning tags
//! (`<thinking>`), injected `<system-reminder>` blocks. A line-dropping
//! compressor that removes the *interior* of a code fence — or one of its two
//! delimiters — leaves a dangling ```` ``` ```` that corrupts everything after
//! it. The same goes for splitting a `<tool_call>…</tool_call>` region.
//!
//! [`protected_line_mask`] marks every line that must survive so boundaries
//! stay intact: both fence delimiters + everything between them, and any line
//! carrying a tool-call / XML structural tag. The line compressors
//! ([`super::log_compressor`], [`super::diff_compressor`]) OR this into their
//! keep decision, so compression can never split a protected region.
//!
//! This is the focused safety subset of headroom's `tag_protector.rs`
//! placeholder-swap (its `protect_tags`/`restore_tags` shield an ML text
//! compressor — NEOTH's structural compressors don't do ML text rewriting, so
//! a line-level guard is the right, consumer-backed primitive here).

use std::sync::LazyLock;

use regex::Regex;

/// Structural tags whose lines must never be dropped (tool calls, reasoning,
/// injected reminders). Matched case-insensitively, open or close form. Plain
/// HTML prose markup (`<div>`, `<p>`, …) is deliberately NOT protected.
static PROTECTED_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)</?\s*(tool_call|tool_use|tool_result|function_calls?|antml:invoke|antml:parameter|invoke|thinking|system-reminder|system_reminder|headroom)\b",
    )
    .unwrap()
});

/// True if `line` (trimmed) is a Markdown code-fence delimiter: ```` ``` ````
/// or `~~~`, optionally followed by a language tag.
pub fn is_fence_delimiter(line: &str) -> bool {
    // Three or more backticks/tildes at the start (after optional indent),
    // optionally followed by a free-form info/language string.
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

/// Mark which lines must be kept to preserve structural boundaries.
///
/// - Inside a ```` ``` ````/`~~~` fence: every line, including both
///   delimiters, is protected (dropping any would dangle the fence).
/// - Outside a fence: any line carrying a protected structural tag.
///
/// Returns a mask aligned 1:1 with `text.lines()`.
pub fn protected_line_mask(text: &str) -> Vec<bool> {
    let mut mask = Vec::new();
    let mut in_fence = false;
    for line in text.lines() {
        if is_fence_delimiter(line) {
            // The delimiter line itself is protected; toggle fence state.
            mask.push(true);
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            mask.push(true);
            continue;
        }
        mask.push(PROTECTED_TAG_RE.is_match(line));
    }
    mask
}

/// Convenience: does `text` contain any protected region at all? Lets a
/// compressor cheaply skip the OR-in step when there's nothing to protect.
pub fn has_protected_regions(text: &str) -> bool {
    text.lines()
        .any(|line| is_fence_delimiter(line) || PROTECTED_TAG_RE.is_match(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_delimiters_recognised() {
        assert!(is_fence_delimiter("```"));
        assert!(is_fence_delimiter("```rust"));
        assert!(is_fence_delimiter("   ```python"));
        assert!(is_fence_delimiter("~~~"));
        assert!(!is_fence_delimiter("let x = `inline`;"));
        assert!(!is_fence_delimiter("plain text"));
    }

    #[test]
    fn fence_interior_and_delimiters_protected() {
        let text = "before\n```rust\nfn main() {}\nlet x = 1;\n```\nafter";
        let mask = protected_line_mask(text);
        // lines: before, ```rust, fn main, let x, ```, after
        assert_eq!(mask, vec![false, true, true, true, true, false]);
    }

    #[test]
    fn tool_call_lines_protected() {
        let text = "log line\n<tool_call name=\"x\">\npayload\n</tool_call>\nmore";
        let mask = protected_line_mask(text);
        // The open + close tag lines are protected; the interior "payload"
        // (not a fence, not a tag) is not — but its boundaries survive.
        assert!(!mask[0]);
        assert!(mask[1]); // <tool_call ...>
        assert!(mask[3]); // </tool_call>
    }

    #[test]
    fn antml_invoke_protected() {
        let text = "x\n<invoke name=\"Bash\">\ny";
        let mask = protected_line_mask(text);
        assert!(mask[1]);
    }

    #[test]
    fn plain_html_not_protected() {
        let text = "<div>hello</div>\n<p>world</p>";
        let mask = protected_line_mask(text);
        assert_eq!(mask, vec![false, false]);
    }

    #[test]
    fn unterminated_fence_protects_to_eof() {
        // A fence that never closes protects everything after the opener —
        // the safest behaviour (we'd rather keep too much than dangle).
        let text = "a\n```\ncode1\ncode2";
        let mask = protected_line_mask(text);
        assert_eq!(mask, vec![false, true, true, true]);
    }

    #[test]
    fn has_protected_regions_detects() {
        assert!(has_protected_regions("a\n```\nx\n```"));
        assert!(has_protected_regions("<thinking>\nx"));
        assert!(!has_protected_regions("plain\nlog\nlines"));
    }

    #[test]
    fn mask_length_matches_line_count() {
        let text = "a\nb\nc\n";
        assert_eq!(protected_line_mask(text).len(), text.lines().count());
    }
}
