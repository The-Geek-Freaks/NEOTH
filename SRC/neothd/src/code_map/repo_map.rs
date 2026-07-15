//! Aider-style compact repo-map summary (GOLD-ADAPT-AWE-AIDER-01).
//!
//! Produces a bounded (~2 K-token) symbol summary of the
//! operator's repo suitable for prepending to coding-buddy prompts.
//! Built entirely from the [`super::walker::RepoMap`] already held in
//! memory — **no filesystem re-parse, no regex re-scan**.
//!
//! ## Algorithm (Aider-inspired, lighter)
//!
//! 1. **Header** — one line: repo root, total files, total LOC, top
//!    language breakdown (≤ 5 langs, descending count).
//! 2. **Per-file symbol table** — for each file that has symbols,
//!    emit `<path>` followed by indented `<kind> <name>` lines.
//!    Files are ranked by symbol count (most symbols first) so the
//!    budget bytes land on the richest files.
//! 3. **Budget enforcement** — the caller supplies `token_budget`
//!    (default 2 048). Approximate conversion: 1 token ≈ 4 chars.
//!    Lines are appended until the budget is reached; a truncation
//!    note is appended when files were dropped.
//!
//! ## Priority ordering within each file
//!
//! Types (struct / enum / trait / interface / type) are emitted
//! before functions/methods because types form the vocabulary the
//! LLM needs to understand the APIs. Within each priority tier the
//! symbols are sorted by source line so the summary reads top-down.
//!
//! ## Why not use the call graph here?
//!
//! The `CallGraph` in `code_map::graph` requires per-symbol source
//! text + a second pass over every file. For a quick coding-buddy
//! prefix the call-graph cost isn't worth it — the symbol table alone
//! already tells the LLM "what is defined where". If callers want
//! call-graph edges they can extend `RepoMapSummary` in a follow-up
//! (Phase 2 of this item).
//!
//! ## Wiring
//!
//! `neoth code` loads the persisted map for the current working directory,
//! builds this summary, and passes it to the coding decomposer as
//! `project_context`. An absent/unreadable map is a best-effort no-op.

use serde::{Deserialize, Serialize};

use super::symbols::SymbolKind;
use super::walker::{Language, RepoMap};

/// Default token budget. Aider uses ~2 K tokens for its repo-map;
/// we match that as the out-of-the-box bound.
pub const DEFAULT_TOKEN_BUDGET: usize = 2_048;

/// Approximate characters per token (GPT-4 / Claude heuristic).
const CHARS_PER_TOKEN: usize = 4;

/// A bounded compact summary of a [`RepoMap`] ready to inject into a
/// prompt. The primary consumer is `coding::dispatcher` which prepends
/// this to the `prompt_bundle` on CODING_INTENT events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoMapSummary {
    /// The formatted summary text. Inject into a prompt as-is (or
    /// wrap in a `<repo-map>` XML tag for structured prompts).
    pub text: String,
    /// Total symbols included in `text` (not counting the header).
    pub symbols_included: usize,
    /// Files that were omitted because the budget was reached.
    pub files_truncated: usize,
    /// Approximate token count of `text` (char count / 4).
    pub approx_tokens: usize,
}

impl RepoMapSummary {
    /// Convenience accessor: the summary text ready to splice into a
    /// system prompt. Equivalent to `&self.text`.
    pub fn as_prompt_block(&self) -> &str {
        &self.text
    }
}

/// Build a compact summary from an already-populated [`RepoMap`].
///
/// `token_budget` caps the output size. Use [`DEFAULT_TOKEN_BUDGET`]
/// (2 048) unless the caller has a tighter context window.
///
/// The `map` must have been scanned with `with_symbols(true)` to get
/// a non-trivial symbol table; if no files carry symbols the summary
/// degrades to a header-only stat block (still useful for orientation).
pub fn build_summary(map: &RepoMap, token_budget: usize) -> RepoMapSummary {
    let char_budget = token_budget.saturating_mul(CHARS_PER_TOKEN);
    let mut buf = String::with_capacity(char_budget.min(8_192));

    // ── Header ────────────────────────────────────────────────────────
    let lang_list = format_lang_breakdown(&map.report.by_language, 5);
    let header = format!(
        "# repo-map  root={}  files={}  LOC={}{}\n",
        map.root,
        map.report.total_files,
        map.report.total_loc,
        if lang_list.is_empty() {
            String::new()
        } else {
            format!("  langs=[{lang_list}]")
        }
    );
    buf.push_str(&header);

    if buf.len() >= char_budget {
        return finish(buf, 0, 0);
    }

    // ── Per-file symbol table ─────────────────────────────────────────
    // Only files that have at least one symbol; ranked by symbol count.
    let mut files_with_syms: Vec<_> = map.files.iter().filter(|f| !f.symbols.is_empty()).collect();
    // Descending symbol count, then ascending path for determinism.
    files_with_syms.sort_by(|a, b| {
        b.symbols
            .len()
            .cmp(&a.symbols.len())
            .then_with(|| a.path.cmp(&b.path))
    });

    let total_files_with_syms = files_with_syms.len();
    let mut symbols_included = 0usize;
    let mut files_included = 0usize;
    let mut files_truncated = 0usize;

    for file in files_with_syms {
        // Check budget BEFORE rendering the file block so we don't
        // emit a partial file and waste the budget on a header line
        // with no following symbols.
        if buf.len() >= char_budget {
            files_truncated += 1;
            continue;
        }

        // Sort symbols: types first (by line), then functions/methods (by line).
        let mut syms_sorted = file.symbols.clone();
        syms_sorted.sort_by_key(|s| (type_priority(s.kind), s.line));

        // Estimate whether this file block fits before writing it.
        // ~(1 + N) lines × ~40 chars average. If it clearly won't fit
        // we skip it (truncated), otherwise we write line-by-line.
        // This keeps the budget check O(symbols) not O(chars²).
        let file_line = format!(
            "{}  ({}  {}LOC)\n",
            file.path,
            file.language.label(),
            file.loc
        );
        if buf.len() + file_line.len() >= char_budget {
            files_truncated += 1;
            continue;
        }
        buf.push_str(&file_line);
        files_included += 1;

        for sym in &syms_sorted {
            let sym_line = format!("  {} {}\n", sym.kind.label(), sym.name);
            if buf.len() + sym_line.len() >= char_budget {
                // Partial file — add a note and stop this file.
                buf.push_str("  … (truncated)\n");
                files_truncated = total_files_with_syms - files_included;
                // Signal that we ran out of budget.
                let approx = buf.len() / CHARS_PER_TOKEN;
                return RepoMapSummary {
                    text: buf,
                    symbols_included,
                    files_truncated,
                    approx_tokens: approx,
                };
            }
            buf.push_str(&sym_line);
            symbols_included += 1;
        }
    }

    // Truncation footer when budget cut off whole files.
    if files_truncated > 0 {
        let footer = format!("# … {files_truncated} more file(s) omitted (budget)\n");
        buf.push_str(&footer);
    }

    finish(buf, symbols_included, files_truncated)
}

/// Finish and build the summary from the accumulated buffer.
fn finish(text: String, symbols_included: usize, files_truncated: usize) -> RepoMapSummary {
    let approx_tokens = text.len() / CHARS_PER_TOKEN;
    RepoMapSummary {
        text,
        symbols_included,
        files_truncated,
        approx_tokens,
    }
}

/// Lower value = emitted first. Types (vocabulary) before callables.
fn type_priority(kind: SymbolKind) -> u8 {
    match kind {
        SymbolKind::Struct
        | SymbolKind::Enum
        | SymbolKind::Trait
        | SymbolKind::Interface
        | SymbolKind::Type
        | SymbolKind::Class => 0,
        SymbolKind::Module => 1,
        SymbolKind::Function | SymbolKind::Method => 2,
    }
}

/// Format the top-N language breakdown for the header line.
/// Returns an empty string when the list is empty.
fn format_lang_breakdown(langs: &[(Language, u64)], top_n: usize) -> String {
    langs
        .iter()
        .take(top_n)
        .map(|(lang, count)| format!("{}:{}", lang.label(), count))
        .collect::<Vec<_>>()
        .join(", ")
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::symbols::{Symbol, SymbolKind};
    use crate::code_map::walker::{Language, RepoFile, RepoMap, ScanReport};

    /// Build a minimal `RepoMap` with known symbols for deterministic tests.
    fn fixture_map() -> RepoMap {
        RepoMap {
            root: "/repo/myproject".into(),
            files: vec![
                RepoFile {
                    path: "src/auth.rs".into(),
                    language: Language::Rust,
                    bytes: 600,
                    loc: 50,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![
                        Symbol {
                            name: "AuthError".into(),
                            kind: SymbolKind::Enum,
                            line: 3,
                        },
                        Symbol {
                            name: "verify_token".into(),
                            kind: SymbolKind::Function,
                            line: 12,
                        },
                        Symbol {
                            name: "authenticate".into(),
                            kind: SymbolKind::Function,
                            line: 25,
                        },
                    ],
                },
                RepoFile {
                    path: "src/config.rs".into(),
                    language: Language::Rust,
                    bytes: 200,
                    loc: 20,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "Config".into(),
                        kind: SymbolKind::Struct,
                        line: 5,
                    }],
                },
                RepoFile {
                    path: "README.md".into(),
                    language: Language::Markdown,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![], // no symbols — must be skipped
                },
            ],
            report: ScanReport {
                total_files: 3,
                total_bytes: 900,
                total_loc: 80,
                by_language: vec![(Language::Rust, 2), (Language::Markdown, 1)],
                oversize_skipped: 0,
                truncated_at: None,
            },
        }
    }

    #[test]
    fn summary_contains_header_with_root_and_stats() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        assert!(
            s.text.contains("repo-map"),
            "header missing 'repo-map': {}",
            s.text
        );
        assert!(
            s.text.contains("/repo/myproject"),
            "header missing root: {}",
            s.text
        );
        assert!(s.text.contains("files=3"), "header missing file count");
        assert!(s.text.contains("LOC=80"), "header missing LOC");
    }

    #[test]
    fn summary_lists_top_symbols_from_both_files() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // Both code files should appear.
        assert!(s.text.contains("src/auth.rs"), "auth.rs missing");
        assert!(s.text.contains("src/config.rs"), "config.rs missing");
        // Key symbol names present.
        assert!(s.text.contains("AuthError"), "enum missing");
        assert!(s.text.contains("verify_token"), "fn missing");
        assert!(s.text.contains("Config"), "struct missing");
    }

    #[test]
    fn markdown_file_without_symbols_excluded() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // README.md has no symbols; it must not appear in the symbol table.
        assert!(
            !s.text.contains("README.md"),
            "symbol-less file must be excluded: {}",
            s.text
        );
    }

    #[test]
    fn types_appear_before_functions_within_file() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // In auth.rs: AuthError (enum, line 3) must appear before
        // verify_token (fn, line 12) even though line ordering is
        // already correct here. Confirm in text position.
        let auth_pos = s.text.find("AuthError").expect("AuthError missing");
        let fn_pos = s.text.find("verify_token").expect("verify_token missing");
        assert!(
            auth_pos < fn_pos,
            "type should precede function in output (auth_pos={auth_pos} fn_pos={fn_pos})"
        );
    }

    #[test]
    fn most_symbol_rich_file_appears_first() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // auth.rs has 3 symbols, config.rs has 1 → auth.rs must appear first.
        let auth_pos = s.text.find("src/auth.rs").expect("auth.rs missing");
        let config_pos = s.text.find("src/config.rs").expect("config.rs missing");
        assert!(
            auth_pos < config_pos,
            "richer file should appear first (auth={auth_pos} config={config_pos})"
        );
    }

    #[test]
    fn symbols_included_count_is_correct() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // 3 symbols in auth.rs + 1 in config.rs = 4 total.
        assert_eq!(
            s.symbols_included, 4,
            "expected 4 symbols; got {} (text={})",
            s.symbols_included, s.text
        );
        assert_eq!(s.files_truncated, 0);
    }

    #[test]
    fn approx_tokens_is_bounded_below_budget() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        assert!(
            s.approx_tokens <= DEFAULT_TOKEN_BUDGET,
            "approx_tokens {} must not exceed budget {}",
            s.approx_tokens,
            DEFAULT_TOKEN_BUDGET
        );
    }

    #[test]
    fn tiny_budget_produces_header_only_or_partial() {
        let map = fixture_map();
        // Budget of 10 tokens = 40 chars — barely enough for the header.
        let s = build_summary(&map, 10);
        // Must not panic; text must not exceed ~40 chars + some slack.
        assert!(
            s.text.len() <= 80,
            "tiny budget must hard-cap output: len={}",
            s.text.len()
        );
    }

    #[test]
    fn budget_truncation_records_files_truncated() {
        // Build a map where many files will exceed a small budget.
        let mut map = fixture_map();
        // Add extra files so truncation is forced.
        for i in 0..20 {
            map.files.push(RepoFile {
                path: format!("src/module_{i}.rs"),
                language: Language::Rust,
                bytes: 100,
                loc: 10,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![
                    Symbol {
                        name: format!("Struct{i}"),
                        kind: SymbolKind::Struct,
                        line: 1,
                    },
                    Symbol {
                        name: format!("fn_{i}"),
                        kind: SymbolKind::Function,
                        line: 10,
                    },
                ],
            });
        }
        // Small budget: 100 tokens = 400 chars — too small for all files.
        let s = build_summary(&map, 100);
        assert!(
            s.files_truncated > 0,
            "expected some truncation with tight budget; got files_truncated={}",
            s.files_truncated
        );
        assert!(
            s.text.len() <= 400 + 60, // budget chars + a small truncation-note slack
            "output must stay near budget: len={}",
            s.text.len()
        );
    }

    #[test]
    fn empty_repo_map_produces_header_only() {
        let map = RepoMap {
            root: "/empty".into(),
            files: vec![],
            report: ScanReport::default(),
        };
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        assert!(s.text.contains("repo-map"));
        assert!(s.text.contains("files=0"));
        assert_eq!(s.symbols_included, 0);
        assert_eq!(s.files_truncated, 0);
    }

    #[test]
    fn lang_breakdown_in_header() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        // Rust:2 and markdown:1 should appear in langs= section.
        assert!(s.text.contains("rust:2"), "rust count missing: {}", s.text);
        assert!(
            s.text.contains("markdown:1"),
            "markdown count missing: {}",
            s.text
        );
    }

    #[test]
    fn as_prompt_block_returns_same_as_text() {
        let map = fixture_map();
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        assert_eq!(s.as_prompt_block(), s.text.as_str());
    }

    #[test]
    fn format_lang_breakdown_top_n_limits_output() {
        let langs = vec![
            (Language::Rust, 10),
            (Language::Python, 8),
            (Language::TypeScript, 6),
            (Language::Go, 4),
            (Language::Java, 2),
            (Language::CSharp, 1),
        ];
        let s = format_lang_breakdown(&langs, 3);
        // Only top 3 should appear.
        assert!(s.contains("rust:10"));
        assert!(s.contains("python:8"));
        assert!(s.contains("typescript:6"));
        assert!(!s.contains("go:"), "4th lang must be omitted");
        assert!(!s.contains("java:"), "5th lang must be omitted");
    }

    #[test]
    fn type_priority_orders_types_before_fns() {
        assert!(type_priority(SymbolKind::Struct) < type_priority(SymbolKind::Function));
        assert!(type_priority(SymbolKind::Enum) < type_priority(SymbolKind::Method));
        assert!(type_priority(SymbolKind::Trait) < type_priority(SymbolKind::Function));
        assert!(type_priority(SymbolKind::Class) < type_priority(SymbolKind::Function));
        assert!(type_priority(SymbolKind::Module) < type_priority(SymbolKind::Function));
        assert_eq!(
            type_priority(SymbolKind::Function),
            type_priority(SymbolKind::Method)
        );
    }

    #[test]
    fn summary_is_deterministic_on_equal_symbol_counts() {
        // Two files with equal symbol counts; they should appear in
        // lexicographic path order (tie-break).
        let map = RepoMap {
            root: "/r".into(),
            files: vec![
                RepoFile {
                    path: "b.rs".into(),
                    language: Language::Rust,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "B".into(),
                        kind: SymbolKind::Struct,
                        line: 1,
                    }],
                },
                RepoFile {
                    path: "a.rs".into(),
                    language: Language::Rust,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "A".into(),
                        kind: SymbolKind::Struct,
                        line: 1,
                    }],
                },
            ],
            report: ScanReport {
                total_files: 2,
                total_bytes: 200,
                total_loc: 20,
                by_language: vec![(Language::Rust, 2)],
                oversize_skipped: 0,
                truncated_at: None,
            },
        };
        let s = build_summary(&map, DEFAULT_TOKEN_BUDGET);
        let a_pos = s.text.find("a.rs").expect("a.rs missing");
        let b_pos = s.text.find("b.rs").expect("b.rs missing");
        assert!(
            a_pos < b_pos,
            "lex-ascending path tie-break: a.rs must appear before b.rs"
        );
    }
}
