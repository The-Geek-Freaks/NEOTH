//! GOLD-ADAPT-HERMES-07b — log-analysis → patch-proposal → operator-reviewed fix.
//!
//! The monitor cron already detects crashes (`0x49 CRASH_LOG_ALERT` from new
//! `[neoth panic]` lines in `~/.neoth/crash.log`). This module turns that raw
//! signal into something actionable: it CATEGORISES each panic deterministically
//! (no LLM, no I/O on the hot path), emits a structured [`PatchProposal`] with a
//! concrete suggested remediation + the file:line evidence, and STAGES it for
//! the operator to review.
//!
//! ## Operator-reviewed, never auto-applied
//! A proposal is **inert advisory data**. NOTHING here edits source, applies a
//! patch, or restarts anything — self-modification of NEOTH's own source is the
//! highest-blast-radius action there is (see `Action::SelfBinaryReplace`). The
//! operator reviews staged proposals (`neoth self-heal list`) and acts manually.
//! The proposal merely points at the likely site + the likely class of fix.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Coarse class of a panic — drives the suggested remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanicCategory {
    /// `.unwrap()` / `.expect()` on a `None`.
    UnwrapOnNone,
    /// `.unwrap()` / `.expect()` on an `Err`.
    UnwrapOnErr,
    /// Index / slice out of bounds.
    IndexOutOfBounds,
    /// Integer add/sub/mul overflow (debug).
    ArithmeticOverflow,
    /// `RefCell` already-borrowed / already-mutably-borrowed.
    BorrowConflict,
    /// Explicit `panic!` / `unreachable!` / `todo!` reached.
    ExplicitPanic,
    /// Anything the heuristics don't recognise.
    Unknown,
}

impl PanicCategory {
    /// A concrete, category-specific remediation hint for the operator.
    pub fn suggested_action(self) -> &'static str {
        match self {
            Self::UnwrapOnNone => {
                "Replace the `.unwrap()`/`.expect()` on the Option at this site with `?` (if in a \
                 Result fn), `if let Some(..)`, or `.unwrap_or(..)`/`.unwrap_or_default()`."
            }
            Self::UnwrapOnErr => {
                "Propagate the error with `?` or handle it with a `match`/`.unwrap_or_else(..)` — \
                 the Err variant is reachable in production at this site."
            }
            Self::IndexOutOfBounds => {
                "Use `.get(i)` (returns Option) instead of `[i]`, or bounds-check the index before \
                 indexing. A length assumption is violated at this site."
            }
            Self::ArithmeticOverflow => {
                "Use checked_/saturating_/wrapping_ arithmetic (e.g. `a.saturating_sub(b)`) — an \
                 input drives this value out of range."
            }
            Self::BorrowConflict => {
                "A RefCell is borrowed twice overlapping. Narrow the borrow scope (drop the first \
                 borrow before the second) or restructure to avoid re-entrant borrowing."
            }
            Self::ExplicitPanic => {
                "An explicit panic!/unreachable!/todo! was reached — the 'impossible' precondition \
                 is actually reachable. Convert to a recoverable error or fix the precondition."
            }
            Self::Unknown => {
                "Unrecognised panic class — inspect the panic message + backtrace at this site \
                 manually."
            }
        }
    }
}

/// A staged, operator-reviewable remediation proposal derived from one panic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchProposal {
    pub category: PanicCategory,
    /// `file.rs:line` extracted from the panic line, when present.
    pub location: Option<String>,
    /// One-line human summary.
    pub summary: String,
    /// The category-specific remediation hint.
    pub suggested_action: String,
    /// The raw panic line (redaction-safe: a panic message is code, not secrets,
    /// but callers should still run it through `redact_text` before persisting
    /// if the message could interpolate operator data).
    pub evidence: String,
    /// 0.0–1.0 — how confidently the category was recognised.
    pub confidence: f32,
    pub ts_unix: i64,
}

/// Extract a `file.rs:line` location from a panic line, if present. Rust panic
/// messages carry `at src/foo.rs:42:9` (or `panicked at 'msg', src/foo.rs:42`).
fn extract_location(line: &str) -> Option<String> {
    // Find a token containing ".rs:" with a following digit.
    for tok in line.split(|c: char| c.is_whitespace() || c == '\'' || c == ',' || c == '(') {
        if let Some(idx) = tok.find(".rs:") {
            let after = &tok[idx + 4..];
            // Keep file.rs:line (drop a trailing :col / punctuation).
            let line_no: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !line_no.is_empty() {
                let file = &tok[..idx + 3]; // up to and including ".rs"
                // Trim any leading path noise but keep a readable suffix.
                return Some(format!("{file}:{line_no}"));
            }
        }
    }
    None
}

/// Classify a single panic line.
fn categorise(line: &str) -> (PanicCategory, f32) {
    let l = line.to_ascii_lowercase();
    if l.contains("on a `none`") || l.contains("on an `none`") || l.contains("unwrap()` on a `none")
    {
        (PanicCategory::UnwrapOnNone, 0.9)
    } else if l.contains("on an `err`") || l.contains("unwrap()` on an `err") {
        (PanicCategory::UnwrapOnErr, 0.9)
    } else if l.contains("index out of bounds")
        || l.contains("out of range for slice")
        || l.contains("slice index")
    {
        (PanicCategory::IndexOutOfBounds, 0.9)
    } else if l.contains("with overflow") {
        (PanicCategory::ArithmeticOverflow, 0.85)
    } else if l.contains("already borrowed") || l.contains("already mutably borrowed") {
        (PanicCategory::BorrowConflict, 0.85)
    } else if l.contains("internal error: entered unreachable")
        || l.contains("not yet implemented")
        || l.contains("not implemented")
    {
        (PanicCategory::ExplicitPanic, 0.7)
    } else {
        (PanicCategory::Unknown, 0.3)
    }
}

/// Analyse panic lines into proposals (deterministic, no I/O). Lines that don't
/// look like panics are ignored.
pub fn analyse_panic_lines(lines: &[&str], now_unix: i64) -> Vec<PatchProposal> {
    lines
        .iter()
        .filter(|l| l.contains("panic") || l.contains("[neoth panic]"))
        .map(|line| {
            let (category, confidence) = categorise(line);
            let location = extract_location(line);
            let loc_str = location.clone().unwrap_or_else(|| "unknown site".into());
            PatchProposal {
                category,
                location,
                summary: format!("{category:?} panic at {loc_str}"),
                suggested_action: category.suggested_action().to_string(),
                evidence: line.trim().to_string(),
                confidence,
                ts_unix: now_unix,
            }
        })
        .collect()
}

/// Default staging path: `<home>/self_heal/proposals.jsonl`.
pub fn proposals_path(home: &Path) -> PathBuf {
    home.join("self_heal").join("proposals.jsonl")
}

/// Append proposals to the staging store (one JSON object per line).
/// Best-effort: a write error is returned but never panics. NEVER applies.
pub fn stage_proposals(home: &Path, proposals: &[PatchProposal]) -> std::io::Result<()> {
    if proposals.is_empty() {
        return Ok(());
    }
    let path = proposals_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    for p in proposals {
        if let Ok(json) = serde_json::to_string(p) {
            writeln!(f, "{json}")?;
        }
    }
    Ok(())
}

/// Load all staged proposals for operator review (`neoth self-heal list`).
pub fn load_proposals(home: &Path) -> Vec<PatchProposal> {
    let path = proposals_path(home);
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|l| serde_json::from_str::<PatchProposal>(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorises_the_common_panic_classes() {
        let cases = [
            (
                "[neoth panic] thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/cli/chat.rs:512:9",
                PanicCategory::UnwrapOnNone,
                Some("src/cli/chat.rs:512"),
            ),
            (
                "panicked at 'called `Result::unwrap()` on an `Err` value: Timeout', src/net/client.rs:88",
                PanicCategory::UnwrapOnErr,
                Some("src/net/client.rs:88"),
            ),
            (
                "panicked at 'index out of bounds: the len is 3 but the index is 7', src/util/parse.rs:21:5",
                PanicCategory::IndexOutOfBounds,
                Some("src/util/parse.rs:21"),
            ),
            (
                "panicked at 'attempt to subtract with overflow', src/math.rs:9",
                PanicCategory::ArithmeticOverflow,
                Some("src/math.rs:9"),
            ),
            (
                "panicked at 'already borrowed: BorrowMutError', src/state.rs:44",
                PanicCategory::BorrowConflict,
                Some("src/state.rs:44"),
            ),
            (
                "panicked at 'not yet implemented', src/wip.rs:1",
                PanicCategory::ExplicitPanic,
                Some("src/wip.rs:1"),
            ),
        ];
        for (line, want_cat, want_loc) in cases {
            let props = analyse_panic_lines(&[line], 1000);
            assert_eq!(props.len(), 1, "line should yield one proposal: {line}");
            assert_eq!(props[0].category, want_cat, "category for: {line}");
            assert_eq!(
                props[0].location.as_deref(),
                want_loc,
                "location for: {line}"
            );
            assert!(!props[0].suggested_action.is_empty());
        }
    }

    #[test]
    fn non_panic_lines_are_ignored() {
        let lines = ["INFO: started", "DEBUG: tick", "all good"];
        assert!(analyse_panic_lines(&lines, 0).is_empty());
    }

    #[test]
    fn unknown_panic_still_yields_a_low_confidence_proposal() {
        let p = analyse_panic_lines(&["[neoth panic] something weird happened"], 5);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].category, PanicCategory::Unknown);
        assert!(p[0].confidence < 0.5);
    }

    #[test]
    fn stage_and_load_round_trips_and_never_applies() {
        let dir = tempfile::tempdir().unwrap();
        let props = analyse_panic_lines(
            &["panicked at 'called `Option::unwrap()` on a `None` value', src/a.rs:1"],
            42,
        );
        stage_proposals(dir.path(), &props).unwrap();
        let loaded = load_proposals(dir.path());
        assert_eq!(
            loaded, props,
            "proposals round-trip through the staging store"
        );
        // The module exposes no apply()/patch() surface — staging is inert by design.
    }
}
