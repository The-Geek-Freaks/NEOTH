//! Bulk-text → atomic-claims extractor — Phase 28c R-24 GT-6.
//!
//! Operator pastes a markdown blob or points at a file; this module pulls
//! out one factual claim per line. Two implementations:
//!
//!   1. **Heuristic-only** ([`extract_claims_heuristic`]) — layered split:
//!      paragraph (`\n\n`) → list-item regex → sentence boundary
//!      (`unicode-segmentation`) → 800-char hard cap. Drops chunks shorter
//!      than 20 chars and noise prefixes (`Note:`, `TODO`, `TBD`,
//!      `See also`). Used as the cold-start path before any provider is
//!      configured.
//!
//!   2. **LLM-assisted** ([`build_llm_prompt`] + [`parse_llm_output`]) —
//!      the wizard sends each ~800-char chunk to the configured provider
//!      with the system prompt from `memory/neoth_gt_onboarding_pins.md`
//!      ("output each discrete factual claim on its own line"). The
//!      provider call itself lives in the caller (CLI / wizard) so this
//!      module stays sync + dependency-free of the provider stack.
//!
//! Dedup happens via `xxh3_64(normalize(claim))` against an in-memory
//! `HashSet<u64>` for the current pass + the persistent
//! `ground_truth_fingerprints` set (Phase 28c follow-up, not yet wired).
//!
//! Output is always `Vec<Claim>` so the caller can hand them to
//! `groundtruth::insert(Source::BulkText, ...)`.

use std::collections::HashSet;

use unicode_segmentation::UnicodeSegmentation;

/// One atomic claim ready for `idx_groundtruth` insert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub statement: String,
    /// 64-bit fingerprint over the normalised form. Same content from a
    /// re-paste collides and the caller can skip the duplicate.
    pub fingerprint: u64,
}

/// Hard cap per claim. Anything longer is truncated at the next word
/// boundary. Memo: `memory/neoth_gt_onboarding_pins.md`.
pub const MAX_CLAIM_CHARS: usize = 800;
/// Drop chunks shorter than this — they're almost always noise after the
/// split passes (single-word list bullets, "?", etc).
pub const MIN_CLAIM_CHARS: usize = 20;

/// Prefixes that mark a line as TODO/scaffold rather than a fact. Drops
/// the entire chunk when matched (case-sensitive — TODO and Todo are
/// both flagged elsewhere; this set is the exact spec).
const NOISE_PREFIXES: &[&str] = &["Note:", "TODO", "TBD", "See also"];

/// Heuristic-only extractor. Returns deduped claims in document order.
pub fn extract_claims_heuristic(text: &str) -> Vec<Claim> {
    let mut out = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for paragraph in text.split("\n\n") {
        for chunk in split_paragraph(paragraph) {
            let trimmed = chunk.trim();
            if !is_acceptable(trimmed) {
                continue;
            }
            let capped = cap_at_word_boundary(trimmed, MAX_CLAIM_CHARS);
            let normalised = normalise_for_dedup(&capped);
            let fingerprint = xxhash_rust::xxh3::xxh3_64(normalised.as_bytes());
            if seen.insert(fingerprint) {
                out.push(Claim {
                    statement: capped,
                    fingerprint,
                });
            }
        }
    }
    out
}

/// Build the LLM extraction prompt + the user-message body. Returns
/// `(system, user)`. The caller invokes `provider.complete()` with these.
pub fn build_llm_prompt(chunk: &str) -> (String, String) {
    let system = "You are a fact extractor. Given a text, output each discrete, \
                  self-contained factual claim on its own line. One claim per line. \
                  No bullet points. No preamble. No explanation. If a sentence \
                  contains multiple claims, split them."
        .to_string();
    (system, chunk.to_string())
}

/// Parse the LLM response. Each non-empty line becomes one claim,
/// after stripping bullet markers / leading whitespace. Empty input
/// returns an empty vec (caller decides whether that's an error).
pub fn parse_llm_output(response: &str) -> Vec<Claim> {
    let mut out = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for raw in response.lines() {
        let stripped = strip_bullet(raw).trim();
        if !is_acceptable(stripped) {
            continue;
        }
        let capped = cap_at_word_boundary(stripped, MAX_CLAIM_CHARS);
        let normalised = normalise_for_dedup(&capped);
        let fingerprint = xxhash_rust::xxh3::xxh3_64(normalised.as_bytes());
        if seen.insert(fingerprint) {
            out.push(Claim {
                statement: capped,
                fingerprint,
            });
        }
    }
    out
}

// ── internals ───────────────────────────────────────────────────────────────

fn is_acceptable(s: &str) -> bool {
    if s.chars().count() < MIN_CLAIM_CHARS {
        return false;
    }
    for prefix in NOISE_PREFIXES {
        if s.starts_with(prefix) {
            return false;
        }
    }
    true
}

fn strip_bullet(line: &str) -> &str {
    let trimmed = line.trim_start();
    for marker in ["- ", "* ", "• ", "+ "] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return rest;
        }
    }
    // Numbered list: "1. ", "2. ", ...
    if let Some(idx) = trimmed.find(". ") {
        if idx > 0 && idx <= 3 && trimmed[..idx].chars().all(|c| c.is_ascii_digit()) {
            return &trimmed[idx + 2..];
        }
    }
    trimmed
}

fn split_paragraph(paragraph: &str) -> Vec<String> {
    // Layered split: lines that look like list items (`- `, `* `, …) are
    // their own chunks; everything else feeds the sentence splitter.
    let mut chunks = Vec::new();
    let mut sentence_buffer = String::new();
    for line in paragraph.lines() {
        let trimmed = line.trim_start();
        let is_list_item = trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("• ")
            || trimmed.starts_with("+ ")
            || trimmed
                .find(". ")
                .map(|i| i > 0 && i <= 3 && trimmed[..i].chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
        if is_list_item {
            // Flush any prose accumulated above.
            if !sentence_buffer.trim().is_empty() {
                chunks.extend(split_into_sentences(&sentence_buffer));
                sentence_buffer.clear();
            }
            chunks.push(strip_bullet(trimmed).to_string());
        } else {
            sentence_buffer.push_str(trimmed);
            sentence_buffer.push(' ');
        }
    }
    if !sentence_buffer.trim().is_empty() {
        chunks.extend(split_into_sentences(&sentence_buffer));
    }
    chunks
}

fn split_into_sentences(text: &str) -> Vec<String> {
    // `unicode-segmentation` gives us sentence boundaries that respect
    // multilingual punctuation and abbreviations better than naive `.`
    // splitting. Each sentence keeps its trailing punctuation.
    text.unicode_sentences()
        .map(|s| s.trim().to_string())
        .collect()
}

fn cap_at_word_boundary(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    // Find the last word boundary ≤ max chars. `char_indices()` walks
    // code points so multi-byte chars stay intact.
    let mut last_space = 0usize;
    for (idx, ch) in s.char_indices() {
        if idx > max {
            break;
        }
        if ch.is_whitespace() {
            last_space = idx;
        }
    }
    if last_space == 0 {
        // No whitespace inside the cap — hard truncate at the byte boundary
        // closest to `max` code points without splitting a code point.
        let mut end = 0usize;
        for (idx, _) in s.char_indices().take(max) {
            end = idx;
        }
        return s[..end].to_string();
    }
    s[..last_space].to_string()
}

fn normalise_for_dedup(s: &str) -> String {
    // Lower-case + collapse whitespace. Drop trailing punctuation so
    // "X is Y." and "X is Y" hash to the same fingerprint — repeated
    // pastes after a punctuation tweak shouldn't duplicate rows.
    let lower: String = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_was_space = false;
    for ch in lower.chars() {
        if ch.is_whitespace() {
            if !prev_was_space && !out.is_empty() {
                out.push(' ');
            }
            prev_was_space = true;
        } else {
            out.push(ch);
            prev_was_space = false;
        }
    }
    let trimmed: String = out
        .trim_end_matches(['.', '!', '?', ';', ':', ','])
        .to_string();
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_splits_paragraphs_and_drops_short_chunks() {
        let text = "\
            NEOTH builds locally on Windows only.\n\
            Cube is at 100.68.210.50 and must not be remote-rebooted.\n\
            \n\
            Telegram bot uses long-polling for v0.1.\n\
            ok\n";
        let claims = extract_claims_heuristic(text);
        assert!(claims.iter().any(|c| c.statement.contains("Windows")));
        assert!(claims.iter().any(|c| c.statement.contains("100.68.210.50")));
        assert!(claims.iter().any(|c| c.statement.contains("Telegram")));
        // "ok" is below MIN_CLAIM_CHARS → dropped.
        assert!(!claims.iter().any(|c| c.statement == "ok"));
    }

    #[test]
    fn heuristic_dedupes_repeated_claims() {
        let text = "\
            NEOTH never phones home.\n\
            \n\
            NEOTH never phones home.\n\
            \n\
            neoth NEVER phones home.\n";
        let claims = extract_claims_heuristic(text);
        // All three normalise to the same fingerprint.
        let phone_home: Vec<_> = claims
            .iter()
            .filter(|c| c.statement.to_lowercase().contains("phones home"))
            .collect();
        assert_eq!(phone_home.len(), 1, "got {claims:?}");
    }

    #[test]
    fn heuristic_dedup_ignores_trailing_punctuation() {
        let text = "The Cube is 100.68.210.50.\n\nThe Cube is 100.68.210.50";
        let claims = extract_claims_heuristic(text);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn heuristic_skips_noise_prefixes() {
        let text = "\
            TODO: refactor the WAL writer next sprint\n\
            \n\
            Note: this is a placeholder until Phase 28c lands\n\
            \n\
            See also the spec at SPEC_wal.md for details\n\
            \n\
            NEOTH ships with a self-contained binary on every platform.\n";
        let claims = extract_claims_heuristic(text);
        assert_eq!(claims.len(), 1, "noise prefixes must drop");
        assert!(claims[0].statement.contains("self-contained"));
    }

    #[test]
    fn heuristic_splits_list_items() {
        let text = "Bullet list of facts:\n\
            - The Cube runs Unraid with three GPUs at 100.68.210.50\n\
            - The Jarvis VM is on 192.168.178.117 and serves as the gateway\n\
            * Star-bullet works too if the operator prefers it\n\
            1. Numbered list items also work after stripping the prefix\n";
        let claims = extract_claims_heuristic(text);
        assert!(claims.len() >= 3, "expected ≥3 claims, got {claims:?}");
        assert!(claims.iter().any(|c| c.statement.starts_with("The Cube")));
        assert!(claims.iter().any(|c| c.statement.starts_with("Numbered")));
    }

    #[test]
    fn cap_at_word_boundary_respects_max_and_unicode() {
        // Multi-byte chars: each greek letter is 2 bytes in UTF-8. Cap by
        // *characters*, never split a code point.
        let s = "α β γ δ ε ζ η θ ι κ λ μ ν ξ ο π ρ σ τ υ φ χ ψ ω";
        let capped = cap_at_word_boundary(s, 10);
        assert!(
            capped.chars().count() <= 10,
            "got {} chars",
            capped.chars().count()
        );
        // No panic, no broken UTF-8.
        assert!(capped.is_char_boundary(capped.len()));
    }

    #[test]
    fn cap_does_not_truncate_short_input() {
        let s = "short";
        assert_eq!(cap_at_word_boundary(s, 100), "short");
    }

    #[test]
    fn cap_truncates_at_word_boundary() {
        let s = "alpha beta gamma delta epsilon zeta eta";
        // Cap at 18 chars. Last whitespace ≤ 18 is at index 16 (after
        // "gamma"). Function returns `s[..16]` = "alpha beta gamma" — a
        // complete-word truncation that drops the trailing space.
        let capped = cap_at_word_boundary(s, 18);
        assert_eq!(capped, "alpha beta gamma");
        assert!(capped.chars().count() <= 18);
        // Never split a word — the next byte after the cap must be whitespace
        // or end-of-string.
        let next = s.as_bytes().get(capped.len()).copied();
        assert!(
            next == Some(b' ') || next.is_none(),
            "split a word: next byte = {next:?}"
        );
    }

    #[test]
    fn llm_prompt_carries_required_keywords() {
        let (system, user) = build_llm_prompt("the cat is gray");
        assert!(system.contains("fact extractor"));
        assert!(system.contains("One claim per line"));
        assert!(system.contains("No preamble"));
        assert_eq!(user, "the cat is gray");
    }

    #[test]
    fn llm_output_parses_lines_and_strips_bullets() {
        let raw = "- Alex prefers German for chat\n\
                   * Code stays in English\n\
                   1. NEOTH uses MSVC on Windows\n\
                   • Bullet-with-unicode also strips\n\
                   \n\
                   The daemon writes WAL frames before any provider call.\n";
        let claims = parse_llm_output(raw);
        // First claim ("Alex prefers German for chat") is 29 chars — passes MIN.
        assert!(claims.iter().any(|c| c.statement.contains("Alex prefers")));
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("NEOTH uses MSVC"))
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("writes WAL frames"))
        );
        // All bullets stripped:
        assert!(claims.iter().all(|c| !c.statement.starts_with('-')));
        assert!(claims.iter().all(|c| !c.statement.starts_with('*')));
    }

    #[test]
    fn llm_output_dedupes_across_lines() {
        let raw = "Alex builds NEOTH on Windows.\n\
                   alex builds neoth on windows\n\
                   ALEX BUILDS NEOTH ON WINDOWS.\n";
        let claims = parse_llm_output(raw);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn empty_input_returns_no_claims() {
        assert!(extract_claims_heuristic("").is_empty());
        assert!(extract_claims_heuristic("    \n\n   \n").is_empty());
        assert!(parse_llm_output("").is_empty());
    }
}
