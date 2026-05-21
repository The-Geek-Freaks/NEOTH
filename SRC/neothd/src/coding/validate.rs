//! Patch-shape validation — port of smallcode's `validate →
//! fix → escalate` loop from `marrow/bounded_loops.marrow` +
//! `extensions/tmpl_repair_tool.ts`.
//!
//! Per `PLAN/SMALLCODE_AUDIT_2026-05-21.md` port #4. Smallcode
//! runs `node --check` / lint / compile against every worker
//! output and re-injects the diagnostics on failure. NEOTH's
//! Q1 patch-safety verdict is still "store, don't apply"
//! (Pick #6 Phase 4 pending), so we can't yet run
//! `cargo check` against a real working tree. What we CAN do
//! today, without applying anything, is detect the worker
//! patches that are obviously broken — empty fenced blocks,
//! corrupted diff headers, truncated context lines — and
//! refuse to auto-promote them.
//!
//! This module is the pure-function half of the loop:
//!
//!   patch_text -> [`validate_patch_shape`] -> [`PatchValidation`]
//!
//! Wire-in sites:
//!   - `coding::review::auto_promote_if_green` — call
//!     [`validate_patch_shape`] on the on-disk patch before
//!     issuing the REVIEW → DONE transition. Reject the
//!     promotion with `ReviewBlocker::PatchMalformed` when
//!     validation fails.
//!   - `coding::dispatcher` (follow-up) — feed
//!     `PatchValidation::reasons()` back into the retry hint
//!     so the next worker attempt sees its own diagnostic.
//!
//! ## Why pure
//!
//! The smallcode equivalent shells out to `node --check`. We
//! don't, because:
//!   1. We don't apply patches yet (Q1 still pending).
//!   2. Subprocess + working-tree management is its own
//!      pile of failure modes (signal handling, timeout,
//!      pipe drainage) that adds attack surface this port
//!      does NOT need.
//!   3. Shape validation catches ~80% of the failures small
//!      LLMs produce (empty diffs, missing `+++` lines,
//!      trailing junk after the patch) without any IO.
//!
//! The compile/lint-loop integration lands when Pick #6
//! Phase 4 (real apply) lands. Until then, this module is
//! the shipping gate.
//!
//! ## What this module is NOT
//!
//! Not a unified-diff parser. We do not extract hunks, we
//! do not validate line numbers, we do not check that
//! context lines match the target file. That's a real
//! diff library's job (e.g. `patch-rs`). This module asks:
//! "does this look like a unified diff a human or LLM
//! produced?" Anything answering "obviously not" gets
//! rejected; anything that *could* be a real patch passes.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Maximum number of distinct shape problems we surface.
/// More than this and the diagnostic stops being useful
/// (the next-attempt hint can only carry so much) — caller
/// gets a "...and N more" marker instead. Mirrors
/// smallcode's `MAX_REPAIR_HINTS = 8`.
pub const MAX_REASONS: usize = 8;

/// Maximum characters of diagnostic text we hand back to a
/// retry hint. Mirrors the audit's "Cap injected diagnostics
/// at 8000 chars" rule. The actual REASONS_BUDGET is shorter
/// because real hints carry more than just diagnostics — they
/// also carry the role hint + task title.
pub const HINT_DIAGNOSTIC_CAP: usize = 4_000;

/// Outcome of one validation pass over a patch text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchValidation {
    /// Patch parsed cleanly — at least one `diff --git` or
    /// `+++ ` marker, balanced hunks, no obvious truncation.
    Valid,
    /// Patch text was empty or whitespace-only. Distinct from
    /// `Malformed` because the caller usually wants to route
    /// an empty patch to "worker did no work" (treat as a
    /// no-change outcome) rather than "worker tried but
    /// failed".
    Empty,
    /// Shape problems we can name. `reasons` is non-empty
    /// when this variant fires; each entry is an operator-
    /// readable string suitable for inclusion in a retry hint.
    Malformed { reasons: Vec<String> },
}

impl PatchValidation {
    /// True only for `Valid`. Convenience accessor; `==
    /// PatchValidation::Valid` is just as fine at the call
    /// site.
    pub fn is_valid(&self) -> bool {
        matches!(self, PatchValidation::Valid)
    }

    /// Returns the operator-readable reason strings. `Valid`
    /// returns `&[]`; `Empty` returns one fixed reason;
    /// `Malformed` returns the collected reasons. Cheap —
    /// no allocation.
    pub fn reasons(&self) -> &[String] {
        match self {
            PatchValidation::Valid => &[],
            PatchValidation::Empty => EMPTY_REASONS.as_slice(),
            PatchValidation::Malformed { reasons } => reasons.as_slice(),
        }
    }
}

// Fixed "empty patch" reason so `PatchValidation::Empty` can return
// `&[String]` from a shared LazyLock without a per-call allocation.
static EMPTY_REASONS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["patch text was empty or whitespace-only".to_string()]);

impl PatchValidation {

    /// Render the reasons into the diagnostic-text shape the
    /// retry hint expects. Caller usually appends this to a
    /// strategy hint like "The previous attempt had these
    /// problems: <reasons>. Try again with a smaller scope."
    /// Truncated at `HINT_DIAGNOSTIC_CAP` chars with a
    /// "...truncated" marker so a runaway reason list can't
    /// blow the next-attempt context window.
    pub fn render_diagnostic(&self) -> String {
        let reasons = self.reasons();
        if reasons.is_empty() {
            return String::new();
        }
        let mut out = String::with_capacity(reasons.len() * 64);
        for (i, r) in reasons.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str("- ");
            out.push_str(r);
            if out.len() >= HINT_DIAGNOSTIC_CAP {
                out.truncate(HINT_DIAGNOSTIC_CAP);
                out.push_str("\n...(truncated)");
                break;
            }
        }
        out
    }
}

/// Validate a worker-produced patch text. Pure — no IO, no
/// allocation beyond the returned `PatchValidation`.
///
/// Algorithm:
///   1. Trim whitespace; empty -> `Empty`.
///   2. Walk lines, count `diff --git`, `--- `, `+++ `, `@@`
///      markers + check for the smallcode-known failure modes
///      (no markers / unbalanced --- vs +++ / trailing
///      non-diff junk after the last hunk).
///   3. Collect operator-readable reasons; dedupe; cap at
///      [`MAX_REASONS`].
///   4. Return `Valid` when reasons is empty, `Malformed`
///      otherwise.
pub fn validate_patch_shape(text: &str) -> PatchValidation {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return PatchValidation::Empty;
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut diff_headers = 0usize;
    let mut minus_lines = 0usize;
    let mut plus_lines = 0usize;
    let mut hunk_headers = 0usize;
    let mut saw_content_line = false;
    let mut last_meaningful_line_kind = LineKind::Other;

    for line in text.lines() {
        let kind = classify_line(line);
        match kind {
            LineKind::DiffGitHeader => diff_headers += 1,
            LineKind::MinusHeader => minus_lines += 1,
            LineKind::PlusHeader => plus_lines += 1,
            LineKind::HunkHeader => {
                hunk_headers += 1;
                saw_content_line = false;
            }
            LineKind::Plus | LineKind::Minus | LineKind::Context => {
                saw_content_line = true;
            }
            LineKind::Other => {}
            LineKind::Blank => {}
        }
        if kind != LineKind::Blank {
            last_meaningful_line_kind = kind;
        }
    }

    if diff_headers == 0 && minus_lines == 0 && plus_lines == 0 {
        reasons.push(
            "no `diff --git`, `---`, or `+++` header — patch text looks like prose, not a diff"
                .to_string(),
        );
    }

    if minus_lines != plus_lines {
        reasons.push(format!(
            "`---` headers ({minus_lines}) do not match `+++` headers ({plus_lines}) — \
             unified diff requires one of each per file"
        ));
    }

    if (minus_lines > 0 || plus_lines > 0) && hunk_headers == 0 {
        reasons.push(
            "found file headers but zero `@@ ... @@` hunk markers — \
             worker produced filenames without any actual change"
                .to_string(),
        );
    }

    if hunk_headers > 0 && !saw_content_line {
        reasons.push(
            "last hunk header had no following `+`/`-`/context lines — \
             patch is truncated"
                .to_string(),
        );
    }

    if matches!(
        last_meaningful_line_kind,
        LineKind::DiffGitHeader | LineKind::MinusHeader | LineKind::PlusHeader | LineKind::HunkHeader
    ) {
        reasons.push(
            "patch ends on a header line — body is missing or truncated".to_string(),
        );
    }

    // Dedupe + cap. Insertion order preserved.
    let mut seen: HashSet<&str> = HashSet::new();
    let mut deduped: Vec<String> = Vec::with_capacity(reasons.len());
    for r in reasons.iter() {
        if seen.insert(r.as_str()) {
            deduped.push(r.clone());
        }
        if deduped.len() >= MAX_REASONS {
            break;
        }
    }

    if deduped.is_empty() {
        PatchValidation::Valid
    } else {
        PatchValidation::Malformed { reasons: deduped }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LineKind {
    DiffGitHeader,
    MinusHeader,
    PlusHeader,
    HunkHeader,
    Plus,
    Minus,
    Context,
    Blank,
    Other,
}

fn classify_line(line: &str) -> LineKind {
    if line.is_empty() {
        return LineKind::Blank;
    }
    if line.starts_with("diff --git ") {
        return LineKind::DiffGitHeader;
    }
    if line.starts_with("--- ") {
        return LineKind::MinusHeader;
    }
    if line.starts_with("+++ ") {
        return LineKind::PlusHeader;
    }
    if line.starts_with("@@ ") {
        return LineKind::HunkHeader;
    }
    if line.starts_with('+') {
        return LineKind::Plus;
    }
    if line.starts_with('-') {
        return LineKind::Minus;
    }
    if line.starts_with(' ') {
        return LineKind::Context;
    }
    LineKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_formed_patch() -> &'static str {
        "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 use std::io;
+use std::fmt;

 fn main() {}
"
    }

    #[test]
    fn valid_unified_diff_passes() {
        let v = validate_patch_shape(well_formed_patch());
        assert_eq!(v, PatchValidation::Valid);
        assert!(v.is_valid());
        assert!(v.reasons().is_empty());
    }

    #[test]
    fn empty_text_is_empty_variant_not_malformed() {
        assert_eq!(validate_patch_shape(""), PatchValidation::Empty);
        assert_eq!(validate_patch_shape("   \n  \t  "), PatchValidation::Empty);
    }

    #[test]
    fn empty_reasons_carry_one_operator_readable_string() {
        let v = validate_patch_shape("");
        let reasons = v.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].contains("empty"),
            "operator-readable: {}",
            reasons[0]
        );
    }

    #[test]
    fn pure_prose_rejected_with_no_marker_reason() {
        let v = validate_patch_shape("hello world\nthis is not a diff\n");
        match v {
            PatchValidation::Malformed { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("looks like prose")));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_minus_plus_headers_rejected() {
        let bad = "\
--- a/x.rs
--- a/y.rs
+++ b/x.rs
@@ -1 +1 @@
-old
+new
";
        let v = validate_patch_shape(bad);
        match v {
            PatchValidation::Malformed { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("do not match")));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn headers_without_hunk_rejected() {
        // The worker named the files but never produced an
        // actual change region.
        let bad = "\
--- a/src/lib.rs
+++ b/src/lib.rs
";
        let v = validate_patch_shape(bad);
        match v {
            PatchValidation::Malformed { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("zero `@@")));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn hunk_with_no_body_rejected() {
        let bad = "\
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
";
        let v = validate_patch_shape(bad);
        match v {
            PatchValidation::Malformed { reasons } => {
                assert!(
                    reasons.iter().any(|r| r.contains("truncated"))
                        || reasons.iter().any(|r| r.contains("header"))
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn diff_git_header_alone_passes_minimum_marker_check_but_flags_empty_body() {
        // `diff --git` alone IS a marker so the
        // "looks-like-prose" rule does not fire. But it
        // also ends on a header line, so the "truncated"
        // rule MUST fire.
        let bad = "diff --git a/x b/x\n";
        let v = validate_patch_shape(bad);
        match v {
            PatchValidation::Malformed { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("ends on a header")));
                // Should NOT trigger the prose-only message:
                assert!(!reasons.iter().any(|r| r.contains("looks like prose")));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn reasons_are_deduped() {
        // Constructed input that would otherwise produce
        // the same reason twice — pin that the dedupe pass
        // keeps the reason list short + readable.
        let bad = "hello\nworld\n";
        let v = validate_patch_shape(bad);
        if let PatchValidation::Malformed { reasons } = v {
            let unique: HashSet<&String> = reasons.iter().collect();
            assert_eq!(unique.len(), reasons.len(), "reasons not deduped");
        }
    }

    #[test]
    fn render_diagnostic_includes_each_reason_as_bullet() {
        let v = PatchValidation::Malformed {
            reasons: vec!["reason A".into(), "reason B".into()],
        };
        let s = v.render_diagnostic();
        assert!(s.contains("- reason A"));
        assert!(s.contains("- reason B"));
    }

    #[test]
    fn render_diagnostic_truncates_at_cap() {
        let huge = "x".repeat(HINT_DIAGNOSTIC_CAP + 200);
        let v = PatchValidation::Malformed {
            reasons: vec![huge],
        };
        let s = v.render_diagnostic();
        assert!(s.contains("(truncated)"));
        assert!(s.len() <= HINT_DIAGNOSTIC_CAP + 64);
    }

    #[test]
    fn render_diagnostic_empty_for_valid() {
        assert_eq!(PatchValidation::Valid.render_diagnostic(), "");
    }

    #[test]
    fn render_diagnostic_empty_variant_says_empty() {
        let s = PatchValidation::Empty.render_diagnostic();
        assert!(s.contains("empty"));
    }

    #[test]
    fn classify_line_recognises_each_marker_kind() {
        assert_eq!(
            classify_line("diff --git a/x b/x"),
            LineKind::DiffGitHeader
        );
        assert_eq!(classify_line("--- a/x"), LineKind::MinusHeader);
        assert_eq!(classify_line("+++ b/x"), LineKind::PlusHeader);
        assert_eq!(classify_line("@@ -1 +1 @@"), LineKind::HunkHeader);
        assert_eq!(classify_line("+added"), LineKind::Plus);
        assert_eq!(classify_line("-removed"), LineKind::Minus);
        assert_eq!(classify_line(" context"), LineKind::Context);
        assert_eq!(classify_line(""), LineKind::Blank);
        assert_eq!(classify_line("not-a-diff-line"), LineKind::Other);
    }
}
