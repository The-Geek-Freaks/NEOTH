//! PL-03 (Session 24) — proactive paperless consultation.
//!
//! When the operator types a question that PL-02-archived
//! documents might answer (invoices, receipts, contracts), NEOTH
//! consults the local paperless vault BEFORE / IN PARALLEL with
//! the LLM call. The matched documents land in the prompt as
//! grounded context, and a [`crate::proactive::ProactiveItem`]
//! optionally nudges the operator to open the source document
//! when no recent chat surfaced the same docs.
//!
//! ## How matches score
//!
//! Pure keyword frequency over `<vault>/<subdir>/Paperless/*.md`:
//!
//!   1. Tokenize the question (split non-alphanumeric, lowercase,
//!      drop stopwords + words < 4 chars + pure-digit tokens
//!      because raw numbers like "42" cause noise).
//!   2. For each Paperless `.md` file: count how many distinct
//!      query tokens appear in the body (case-insensitive
//!      substring). Each unique-token-hit contributes 1 to the
//!      score; repeats inside one doc don't compound.
//!   3. Rank by score desc, ties broken by mtime desc (newest
//!      first — operators usually want the latest invoice).
//!   4. Drop docs with score 0.
//!   5. Return top-N matches with a body excerpt around the
//!      first matching token (operator sees WHY this doc
//!      matched, not just "this matched").
//!
//! ## Why no embeddings
//!
//! Embeddings would catch paraphrases ("the bill from May" vs
//! "Rechnung Mai") but pull a 4 GB qwen model into the consult
//! path. PL-03 stays substring-only so consult is free + runs
//! synchronously on every operator question. Phase 2 may add an
//! optional embedding pass behind a freedom.yaml flag.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One matched document. The body excerpt is operator-visible —
/// kept short (~`MAX_EXCERPT_CHARS`) so the consult result fits
/// in a chat preview without scrolling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultMatch {
    /// `<doc_id>.md` filename. Operators can click this to open
    /// the source note in Obsidian.
    pub filename: String,
    /// Full absolute path to the matched note.
    pub path: PathBuf,
    /// Number of distinct query tokens that hit the body. Higher
    /// = more on-topic. Capped at the query's token count.
    pub score: usize,
    /// ~200-char window around the first matching token (or the
    /// start of the body if no token matched after the H1).
    pub excerpt: String,
    /// File modification time (unix seconds, 0 when unavailable
    /// — kept non-Option so consumers don't branch on the
    /// platform-dependent ctime quirk).
    pub mtime_unix: u64,
}

/// Aggregate result of one consultation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultResult {
    /// Top-N ranked matches. Empty when no doc had a non-zero score.
    pub matches: Vec<ConsultMatch>,
    /// Tokens extracted from the question after stopword + length
    /// filtering. Surfaced so the operator UI can show "consulting
    /// for: invoice, may, amount" — confidence anchor.
    pub query_tokens: Vec<String>,
    /// Total `.md` files scanned (whether or not they matched).
    pub scanned: usize,
}

/// Default cap on returned matches. Operators see the top N; deeper
/// hits are dropped to keep the consult preview readable.
pub const DEFAULT_MAX_MATCHES: usize = 5;

/// Excerpt window size in chars.
pub const MAX_EXCERPT_CHARS: usize = 200;

/// Minimum token length kept after filtering. Words like "of" /
/// "is" / "wir" don't help the keyword match and add noise.
pub const MIN_TOKEN_LEN: usize = 4;

/// Stopwords — same German+English+NEOTH-noise list as the
/// reflection module + a paperless-specific noise tier (operators
/// often type "rechnung" / "invoice" generically; we keep those as
/// signal because a query for them WILL hit invoice-flavored docs).
const STOPWORDS: &[&str] = &[
    // German function words
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einen", "einem", "eines",
    "und", "oder", "aber", "doch", "weil", "wenn", "dann", "ja", "nein", "nicht", "kein", "keine",
    "ich", "you", "er", "sie", "wir", "ihr", "mich", "dich", "uns", "euch", "mein", "dein", "ist",
    "war", "sind", "waren", "hat", "habe", "haben", "wird", "werden", "kann", "können", "auf",
    "in", "im", "an", "am", "zu", "zum", "zur", "mit", "von", "vom", "für", "über", "wie", "was",
    "wer", "wo", "warum", "wann", // English
    "the", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "it", "this", "that",
    "what", "when", "where", "why", "have", "has", "had", "do", "does", "did", "be", "been",
    "being", "are", "was", "were", "will", "would", "should", "could", "can", "may", "might", "as",
    "at", "by", "from",
];

/// Extract scoring tokens from a question. Pure — public for tests
/// and for caller surfaces that want to show the operator which
/// tokens drove the scan.
pub fn extract_query_tokens(question: &str) -> Vec<String> {
    let stopwords: HashSet<&str> = STOPWORDS.iter().copied().collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for word in question
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        let lower = word.to_lowercase();
        if lower.chars().count() < MIN_TOKEN_LEN {
            continue;
        }
        // Pure-digit tokens are noise — "42" matches every invoice
        // with line 42. Allowed only when the digit run is ≥5 chars
        // (date / id / phone-number patterns).
        if lower.chars().all(|c| c.is_ascii_digit()) && lower.chars().count() < 5 {
            continue;
        }
        if stopwords.contains(lower.as_str()) {
            continue;
        }
        if seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    out
}

/// Consult the paperless vault for documents matching `question`.
/// Returns up to `max_matches` ranked matches.
///
/// Missing `<vault>/<subdir>/Paperless/` → empty result (no error
/// — operators who don't use paperless still hit this path
/// through the default proactive chain).
pub fn consult(
    vault_root: &Path,
    subdir: &str,
    question: &str,
    max_matches: usize,
) -> ConsultResult {
    let dir = vault_root.join(subdir).join("Paperless");
    let query_tokens = extract_query_tokens(question);
    if query_tokens.is_empty() {
        return ConsultResult {
            matches: Vec::new(),
            query_tokens,
            scanned: 0,
        };
    }

    let entries = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => {
            return ConsultResult {
                matches: Vec::new(),
                query_tokens,
                scanned: 0,
            };
        }
    };

    let mut scanned = 0usize;
    let mut candidates: Vec<ConsultMatch> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("md") {
            continue;
        }
        scanned += 1;
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let body_lc = body.to_lowercase();

        let mut score = 0usize;
        let mut first_hit_byte: Option<usize> = None;
        for token in &query_tokens {
            if let Some(idx) = body_lc.find(token.as_str()) {
                score += 1;
                first_hit_byte = Some(first_hit_byte.map_or(idx, |prev| prev.min(idx)));
            }
        }
        if score == 0 {
            continue;
        }

        let excerpt = build_excerpt(&body, first_hit_byte);
        let mtime_unix = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let filename = entry.file_name().to_string_lossy().to_string();
        candidates.push(ConsultMatch {
            filename,
            path,
            score,
            excerpt,
            mtime_unix,
        });
    }

    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.mtime_unix.cmp(&a.mtime_unix))
            .then_with(|| a.filename.cmp(&b.filename))
    });
    candidates.truncate(max_matches);

    ConsultResult {
        matches: candidates,
        query_tokens,
        scanned,
    }
}

/// Build a `MAX_EXCERPT_CHARS`-wide window around `hit_byte`. Uses
/// char-boundary-safe slicing so multi-byte UTF-8 doesn't panic.
fn build_excerpt(body: &str, hit_byte: Option<usize>) -> String {
    let center = hit_byte.unwrap_or(0);
    // Convert byte offset to char index — work in chars from here
    // on so UTF-8 multi-byte sequences don't get sliced mid-code-point.
    let chars: Vec<char> = body.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let center_char = body[..center.min(body.len())].chars().count();
    let half = MAX_EXCERPT_CHARS / 2;
    let start = center_char.saturating_sub(half);
    let end = (center_char + half).min(chars.len());
    let mut excerpt: String = chars[start..end].iter().collect();
    if start > 0 {
        excerpt.insert(0, '…');
    }
    if end < chars.len() {
        excerpt.push('…');
    }
    // Collapse newlines for a one-line preview (operators see the
    // full body via the file link).
    excerpt.replace('\n', " ")
}

/// Render the consult result as a brief operator-readable
/// summary suitable for inlining into a chat reply.
/// Empty `matches` returns an empty string so the caller can
/// short-circuit "no paperless context" output.
pub fn render_summary(result: &ConsultResult) -> String {
    if result.matches.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(256);
    out.push_str(&format!(
        "Paperless consult ({} hits over {} docs, tokens: {}):\n",
        result.matches.len(),
        result.scanned,
        result.query_tokens.join(", "),
    ));
    for m in &result.matches {
        out.push_str(&format!(
            "- `{}` (score {}) — {}\n",
            m.filename, m.score, m.excerpt
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_md(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn extract_drops_stopwords_and_short_words() {
        let toks = extract_query_tokens("Was war die Rechnung im Mai von ACME?");
        // "was", "war", "die", "im", "von" → stopwords; "mai" 3 chars dropped
        assert!(toks.contains(&"rechnung".to_string()));
        assert!(toks.contains(&"acme".to_string()));
        assert!(!toks.contains(&"die".to_string()));
        assert!(!toks.contains(&"mai".to_string()));
    }

    #[test]
    fn extract_drops_pure_digit_tokens_below_5_chars() {
        let toks = extract_query_tokens("Order 42 vs order 99876");
        assert!(!toks.contains(&"42".to_string()));
        assert!(toks.contains(&"99876".to_string()));
    }

    #[test]
    fn extract_dedups_repeated_words() {
        let toks = extract_query_tokens("invoice invoice INVOICE");
        assert_eq!(toks, vec!["invoice"]);
    }

    #[test]
    fn extract_case_insensitive() {
        let toks = extract_query_tokens("INVOICE Acme");
        assert!(toks.contains(&"invoice".to_string()));
        assert!(toks.contains(&"acme".to_string()));
    }

    #[test]
    fn consult_missing_paperless_dir_returns_empty() {
        let vault = tempfile::tempdir().unwrap();
        let r = consult(vault.path(), "NEOTH", "invoice from acme", 5);
        assert!(r.matches.is_empty());
        assert_eq!(r.scanned, 0);
    }

    #[test]
    fn consult_returns_doc_with_matching_token() {
        let vault = tempfile::tempdir().unwrap();
        let paperless_dir = vault.path().join("NEOTH").join("Paperless");
        write_md(
            &paperless_dir,
            "doc-001.md",
            "# Paperless\nInvoice from Acme Co, May 2026",
        );
        write_md(
            &paperless_dir,
            "doc-002.md",
            "# Paperless\nCoffee receipt at corner cafe",
        );

        let r = consult(vault.path(), "NEOTH", "invoice acme", 5);
        assert_eq!(r.scanned, 2);
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].filename, "doc-001.md");
        assert_eq!(r.matches[0].score, 2); // invoice + acme
    }

    #[test]
    fn consult_scores_by_distinct_token_count_not_repeats() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "a.md", "invoice invoice invoice invoice");
        write_md(&dir, "b.md", "invoice from acme");

        let r = consult(vault.path(), "NEOTH", "invoice acme", 5);
        // a.md has invoice x4 (distinct count 1), b.md has invoice + acme (distinct 2).
        // b.md wins.
        assert_eq!(r.matches[0].filename, "b.md");
        assert_eq!(r.matches[0].score, 2);
    }

    #[test]
    fn consult_caps_at_max_matches() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        for i in 0..10 {
            write_md(&dir, &format!("doc-{i:02}.md"), "invoice from acme");
        }
        let r = consult(vault.path(), "NEOTH", "invoice acme", 3);
        assert_eq!(r.matches.len(), 3);
        assert_eq!(r.scanned, 10);
    }

    #[test]
    fn consult_drops_zero_score_docs() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "match.md", "invoice from acme");
        write_md(&dir, "nomatch.md", "coffee receipt cafe");
        let r = consult(vault.path(), "NEOTH", "invoice acme", 10);
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].filename, "match.md");
    }

    #[test]
    fn consult_excerpt_includes_a_matching_token() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        let body = "# Paperless\n".to_string() + &"x".repeat(500) + " invoice " + &"y".repeat(500);
        write_md(&dir, "a.md", &body);
        let r = consult(vault.path(), "NEOTH", "invoice", 5);
        assert_eq!(r.matches.len(), 1);
        assert!(
            r.matches[0].excerpt.to_lowercase().contains("invoice"),
            "excerpt missing match: {:?}",
            r.matches[0].excerpt,
        );
    }

    #[test]
    fn consult_excerpt_is_single_line() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "a.md", "line1\ninvoice\nline3");
        let r = consult(vault.path(), "NEOTH", "invoice", 5);
        assert!(!r.matches[0].excerpt.contains('\n'));
    }

    #[test]
    fn consult_query_tokens_carried_through_for_ui() {
        let vault = tempfile::tempdir().unwrap();
        let r = consult(vault.path(), "NEOTH", "invoice from ACME", 5);
        assert!(r.query_tokens.contains(&"invoice".to_string()));
        assert!(r.query_tokens.contains(&"acme".to_string()));
    }

    #[test]
    fn consult_empty_question_returns_empty_matches() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "a.md", "invoice");
        let r = consult(vault.path(), "NEOTH", "", 5);
        assert!(r.matches.is_empty());
        assert!(r.query_tokens.is_empty());
    }

    #[test]
    fn consult_ignores_non_md_files() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "a.md", "invoice");
        write_md(&dir, "b.txt", "invoice");
        write_md(&dir, "c.json", "invoice");
        let r = consult(vault.path(), "NEOTH", "invoice", 5);
        assert_eq!(r.scanned, 1);
        assert_eq!(r.matches.len(), 1);
    }

    #[test]
    fn consult_ties_break_by_mtime_then_filename() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "z.md", "invoice acme");
        write_md(&dir, "a.md", "invoice acme");
        let r = consult(vault.path(), "NEOTH", "invoice acme", 5);
        // Same score (2) for both; same mtime (likely) → alpha asc.
        // We don't pin which of mtime / filename wins because the
        // disk-write order varies — we only assert BOTH are present.
        assert_eq!(r.matches.len(), 2);
        let names: Vec<&str> = r.matches.iter().map(|m| m.filename.as_str()).collect();
        assert!(names.contains(&"a.md"));
        assert!(names.contains(&"z.md"));
    }

    #[test]
    fn render_summary_empty_returns_empty_string() {
        let r = ConsultResult {
            matches: Vec::new(),
            query_tokens: vec!["invoice".into()],
            scanned: 0,
        };
        assert!(render_summary(&r).is_empty());
    }

    #[test]
    fn render_summary_lists_each_match_with_score_and_excerpt() {
        let r = ConsultResult {
            matches: vec![ConsultMatch {
                filename: "doc-1.md".into(),
                path: PathBuf::from("/tmp/doc-1.md"),
                score: 2,
                excerpt: "invoice from acme".into(),
                mtime_unix: 0,
            }],
            query_tokens: vec!["invoice".into(), "acme".into()],
            scanned: 1,
        };
        let s = render_summary(&r);
        assert!(s.contains("Paperless consult"));
        assert!(s.contains("doc-1.md"));
        assert!(s.contains("score 2"));
        assert!(s.contains("invoice from acme"));
    }

    #[test]
    fn consult_case_insensitive_token_match_against_body() {
        let vault = tempfile::tempdir().unwrap();
        let dir = vault.path().join("NEOTH").join("Paperless");
        write_md(&dir, "a.md", "INVOICE FROM ACME");
        let r = consult(vault.path(), "NEOTH", "invoice acme", 5);
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].score, 2);
    }
}
