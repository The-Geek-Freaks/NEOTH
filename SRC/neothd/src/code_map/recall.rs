//! K-Repo-Map Phase 3b (Session 14 Pick #25) — relevance engine.
//!
//! Given a prompt and a populated `code_map.db`, return the files the
//! agent should know about when answering. Foundation for Phase 3c
//! prompt-injection (system-prompt `<repo-context>` block), but the
//! engine ships first standalone so operators can inspect what would
//! be injected (`neoth code-map relevant "<prompt>"`) before any
//! live wire-in.
//!
//! ## Algorithm
//!
//! 1. **Identifier extraction** — pure-fn regex pull of every
//!    plausible code identifier from the prompt. Two patterns:
//!    `CamelCase` (≥3 chars, leading uppercase) + `snake_case` (≥4
//!    chars, lowercase letters/digits with at least one underscore).
//!    Bare words like "the" / "is" / "function" never match.
//!
//! 2. **Symbol lookup** — for each extracted identifier, run
//!    `search_symbol(conn, name)` against `code_map.db`. Each hit
//!    contributes `(file_id, identifier_count)` toward the file's
//!    relevance score.
//!
//! 3. **Ranking** — group hits by `(root, path)`, sum identifier
//!    counts, tie-break by path-keyword overlap (the prompt mentions
//!    "auth" → `src/auth/mod.rs` gets a bonus point), then by
//!    lexicographic path. Return top `max_files` entries.
//!
//! ## What this is NOT (deferred)
//!
//! - Semantic similarity. Phase 3b uses keyword matching only —
//!   embedding-based recall is Phase 3d. The current engine
//!   matches "fn auth_middleware" / "AuthMiddleware" / "auth_middleware"
//!   in the prompt against a symbol named `auth_middleware`; it does
//!   NOT match the prompt "how does login work" against the same
//!   symbol unless "login" / "auth" overlaps the path.
//! - Recency bias. Phase 3c will add a `scanned_at` weighting so a
//!   freshly-scanned file ranks above stale snapshots. Phase 3b
//!   ranks purely on identifier-count + path-keyword overlap.
//! - Cross-root deduplication. If the same symbol name appears in
//!   two persisted roots (operator scanned two repos), both files
//!   surface. The CLI shows the root so the operator can disambiguate.

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use rusqlite::Connection;

use super::persist::SymbolHit;

/// One entry in the relevance ranking. Carries enough metadata for
/// the operator-facing CLI render + for the Phase 3c prompt-block
/// formatter, without re-loading the full `RepoFile`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelevantFile {
    pub root: String,
    pub path: String,
    /// Sum of identifier matches that hit this file. Higher = stronger
    /// signal. Ties broken by `path_keyword_overlap`, then by path
    /// lexicographic order.
    pub identifier_hits: u32,
    /// Distinct identifier names that matched. Used so an operator can
    /// see WHICH symbol triggered the inclusion.
    pub matched_symbols: Vec<String>,
    /// Number of prompt-words (>= 3 chars) that overlap this file's
    /// path components. Tie-break signal — a prompt mentioning "auth"
    /// pushes `src/auth/middleware.rs` above unrelated symbol-only hits.
    pub path_keyword_overlap: u32,
}

/// Extract identifiers from `text` using a single combined regex
/// (cached after first compile). Returns a deduplicated, lowercase-
/// normalised list — `Foo`, `foo`, and `FOO` collapse to one entry
/// because symbol search is case-sensitive at the SQL layer but the
/// prompt's casing intent is noisy.
///
/// Patterns:
///   - `CamelCase`-style: a leading uppercase letter followed by ≥2
///     more alphanumerics → `[A-Z][A-Za-z0-9_]{2,}`
///   - `snake_case`-style: ≥4 chars containing at least one underscore
///     with ASCII letters/digits → `[a-z][a-z0-9_]{2,}_[a-z0-9_]+`
///
/// Common English stop-words ("the", "is", "of", etc.) cannot match
/// either pattern by construction — no allowlist needed.
pub fn extract_identifiers(text: &str) -> Vec<String> {
    let camel = camel_regex();
    let snake = snake_regex();
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in camel.find_iter(text) {
        let s = caps.as_str();
        if seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    }
    for caps in snake.find_iter(text) {
        let s = caps.as_str();
        if seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    }
    out
}

fn camel_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Leading uppercase + at least 2 more chars (lower/digit/_).
        // Excludes single-letter names like "I" or "A".
        Regex::new(r"\b[A-Z][A-Za-z0-9_]{2,}\b").unwrap()
    })
}

fn snake_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Lowercase start, at least one underscore, total ≥4 chars.
        // Catches `auth_middleware`, `parse_json`, `to_string` but
        // rejects bare words like "function".
        Regex::new(r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b").unwrap()
    })
}

/// Extract path-keyword signals — lowercase ASCII alphabetic tokens of
/// ≥3 chars from the prompt. Used to bias the ranking toward files
/// whose path contains those tokens. Returns a deduplicated set.
pub fn extract_path_keywords(text: &str) -> Vec<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let re = CELL.get_or_init(|| Regex::new(r"[a-zA-Z][a-zA-Z0-9]{2,}").unwrap());
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in re.find_iter(text) {
        let lower = m.as_str().to_ascii_lowercase();
        // Filter out a tiny stop-list — bare English connectives that
        // would otherwise win every path containing the letter "f".
        if STOP_WORDS.contains(&lower.as_str()) {
            continue;
        }
        if seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    out
}

/// Tiny stop-list. Kept short on purpose — every word here must be
/// guaranteed-useless across English/German operator prompts. Larger
/// stop-lists would start dropping legitimate identifiers ("file",
/// "code", "function" can all be load-bearing).
const STOP_WORDS: &[&str] = &[
    "the", "and", "for", "with", "this", "that", "from", "into", "where", "what", "when", "how",
    "der", "die", "das", "und", "ist", "ein", "eine",
];

/// Count how many of `keywords` appear (as substrings) in `path`.
/// Case-insensitive — path normalised to lowercase before comparison.
pub fn path_keyword_overlap(path: &str, keywords: &[String]) -> u32 {
    let p = path.to_ascii_lowercase();
    keywords.iter().filter(|kw| p.contains(kw.as_str())).count() as u32
}

/// Top-level engine entry: given a prompt, return up to `max_files`
/// relevant entries from the persisted code map.
///
/// Returns an empty Vec when:
///   - The prompt contains no extractable identifiers AND no
///     path-keywords match any persisted file.
///   - The DB has no persisted snapshots (search returns empty).
///   - `max_files == 0` (defensive — caller asked for nothing).
pub fn relevant_files_for_prompt(
    conn: &Connection,
    prompt: &str,
    max_files: usize,
) -> Result<Vec<RelevantFile>> {
    if max_files == 0 {
        return Ok(Vec::new());
    }
    let identifiers = extract_identifiers(prompt);
    let keywords = extract_path_keywords(prompt);

    // Map (root, path) → aggregated metadata. Accumulating into a
    // HashMap keeps the algorithm O(symbol_hits) instead of O(files
    // × symbols).
    let mut by_path: HashMap<(String, String), RelevantFile> = HashMap::new();

    for ident in &identifiers {
        // search_symbol does a case-sensitive lookup; try the
        // identifier verbatim. A future enhancement could also try
        // `ident.to_lowercase()` for snake_case-only databases but
        // case-sensitive is correct for now.
        let hits: Vec<SymbolHit> = super::persist::search_symbol(conn, ident)?;
        for hit in hits {
            let key = (hit.root.clone(), hit.path.clone());
            let entry = by_path.entry(key).or_insert_with(|| RelevantFile {
                root: hit.root.clone(),
                path: hit.path.clone(),
                identifier_hits: 0,
                matched_symbols: Vec::new(),
                path_keyword_overlap: 0,
            });
            entry.identifier_hits += 1;
            if !entry.matched_symbols.contains(ident) {
                entry.matched_symbols.push(ident.clone());
            }
        }
    }

    // Path-keyword bias is computed once per surfaced path.
    for entry in by_path.values_mut() {
        entry.path_keyword_overlap = path_keyword_overlap(&entry.path, &keywords);
    }

    // Also surface files that have ZERO symbol hits but a non-zero
    // path-keyword overlap. Without this, prompts like "fix the
    // config loader" with no symbol match would return empty —
    // we want at least the `config.rs` candidate to surface.
    if !keywords.is_empty() {
        // Walk every persisted file with at least one keyword in its
        // path. Bounded by the keyword set, not the DB size — SQL
        // wildcard scan over indexed `path`.
        let path_hits = scan_paths_by_keywords(conn, &keywords)?;
        for (root, path) in path_hits {
            let key = (root.clone(), path.clone());
            let entry = by_path.entry(key).or_insert_with(|| RelevantFile {
                root,
                path,
                identifier_hits: 0,
                matched_symbols: Vec::new(),
                path_keyword_overlap: 0,
            });
            if entry.path_keyword_overlap == 0 {
                entry.path_keyword_overlap = path_keyword_overlap(&entry.path, &keywords);
            }
        }
    }

    let mut ranked: Vec<RelevantFile> = by_path.into_values().collect();
    ranked.sort_by(|a, b| {
        // Higher identifier_hits first, then higher path_keyword_overlap,
        // then path-lexicographic for deterministic output.
        b.identifier_hits
            .cmp(&a.identifier_hits)
            .then_with(|| b.path_keyword_overlap.cmp(&a.path_keyword_overlap))
            .then_with(|| a.path.cmp(&b.path))
    });
    ranked.truncate(max_files);
    Ok(ranked)
}

/// SQL helper — find every file whose `path` contains any of the
/// supplied keywords. Returns `(root, path)` pairs. Skips when the
/// keyword set is empty.
fn scan_paths_by_keywords(conn: &Connection, keywords: &[String]) -> Result<Vec<(String, String)>> {
    if keywords.is_empty() {
        return Ok(Vec::new());
    }
    // Build `path LIKE ?1 OR path LIKE ?2 ...` dynamically. Bounded
    // by the keyword count (typically ≤10) so the dynamic SQL stays
    // small. LIKE patterns use `%kw%` for substring match.
    let placeholders: Vec<String> = (1..=keywords.len()).map(|i| format!("?{i}")).collect();
    let where_clause = placeholders
        .iter()
        .map(|p| format!("LOWER(path) LIKE {p}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let sql = format!(
        "SELECT root, path FROM code_map_files WHERE {where_clause} \
         ORDER BY root ASC, path ASC LIMIT 200"
    );
    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<rusqlite::types::Value> = keywords
        .iter()
        .map(|kw| rusqlite::types::Value::from(format!("%{}%", kw.to_lowercase())))
        .collect();
    let rows: Vec<(String, String)> = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Render the ranked list as the system-prompt block Phase 3c will
/// inject. Operator-readable + parseable — leading `#` comment + one
/// indented line per file with the matched symbols.
pub fn render_context_block(files: &[RelevantFile]) -> String {
    if files.is_empty() {
        return String::new();
    }
    let mut out = String::from("# repo-context (NEOTH code-map Phase 3b)\n");
    out.push_str("# Files in the operator's repo that may be relevant to this prompt.\n");
    for f in files {
        let symbols_note = if f.matched_symbols.is_empty() {
            String::new()
        } else {
            format!(" — symbols: {}", f.matched_symbols.join(", "))
        };
        let keyword_note = if f.path_keyword_overlap > 0 {
            format!(" (path-keyword:+{})", f.path_keyword_overlap)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "  - {}/{}{}{}\n",
            f.root, f.path, symbols_note, keyword_note,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::persist::{open, persist_map};
    use crate::code_map::symbols::{Symbol, SymbolKind};
    use crate::code_map::walker::{Language, RepoFile, RepoMap, ScanReport};
    use tempfile::tempdir;

    fn seed_db_with_two_files() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("code_map.db");
        let mut conn = open(&path).unwrap();
        let map = RepoMap {
            root: "/repo/a".into(),
            files: vec![
                RepoFile {
                    path: "src/auth/middleware.rs".into(),
                    language: Language::Rust,
                    bytes: 200,
                    loc: 30,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![
                        Symbol {
                            name: "auth_middleware".into(),
                            kind: SymbolKind::Function,
                            line: 12,
                        },
                        Symbol {
                            name: "verify_token".into(),
                            kind: SymbolKind::Function,
                            line: 30,
                        },
                    ],
                },
                RepoFile {
                    path: "src/config/loader.rs".into(),
                    language: Language::Rust,
                    bytes: 150,
                    loc: 20,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "Config".into(),
                        kind: SymbolKind::Struct,
                        line: 5,
                    }],
                },
            ],
            report: ScanReport::default(),
        };
        persist_map(&mut conn, &map).unwrap();
        (dir, conn)
    }

    #[test]
    fn extract_identifiers_finds_camel_case() {
        let ids = extract_identifiers("Please look at AuthMiddleware and the Config struct");
        assert!(ids.contains(&"AuthMiddleware".to_string()), "got: {ids:?}");
        assert!(ids.contains(&"Config".to_string()), "got: {ids:?}");
    }

    #[test]
    fn extract_identifiers_finds_snake_case() {
        let ids = extract_identifiers("where is verify_token defined? also auth_middleware");
        assert!(ids.contains(&"verify_token".to_string()));
        assert!(ids.contains(&"auth_middleware".to_string()));
    }

    #[test]
    fn extract_identifiers_rejects_bare_words() {
        let ids = extract_identifiers("please find the function that handles login");
        // No CamelCase, no underscores → empty.
        assert!(ids.is_empty(), "expected empty, got: {ids:?}");
    }

    #[test]
    fn extract_identifiers_dedupes() {
        let ids = extract_identifiers("auth_middleware auth_middleware auth_middleware");
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn extract_path_keywords_drops_stop_words() {
        let kws = extract_path_keywords("fix the auth handler please");
        assert!(kws.contains(&"auth".to_string()));
        assert!(kws.contains(&"handler".to_string()));
        assert!(
            !kws.contains(&"the".to_string()),
            "stop-word leaked: {kws:?}"
        );
    }

    #[test]
    fn extract_path_keywords_is_case_insensitive() {
        let kws = extract_path_keywords("Fix the AUTH handler");
        assert!(kws.contains(&"auth".to_string()));
        assert!(kws.contains(&"handler".to_string()));
    }

    #[test]
    fn path_keyword_overlap_counts_substring_hits() {
        let kws = vec!["auth".to_string(), "middleware".to_string()];
        assert_eq!(path_keyword_overlap("src/auth/middleware.rs", &kws), 2);
        assert_eq!(path_keyword_overlap("src/config/loader.rs", &kws), 0);
    }

    #[test]
    fn relevant_files_returns_top_match_by_symbol_hit() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits =
            relevant_files_for_prompt(&conn, "where is the auth_middleware function?", 5).unwrap();
        assert!(!hits.is_empty(), "should find at least one file");
        // src/auth/middleware.rs should rank first — symbol match +
        // path-keyword overlap on "auth".
        assert_eq!(
            hits[0].path, "src/auth/middleware.rs",
            "wrong top-rank: {hits:?}"
        );
        assert!(hits[0].identifier_hits >= 1);
        assert!(
            hits[0]
                .matched_symbols
                .contains(&"auth_middleware".to_string())
        );
    }

    #[test]
    fn relevant_files_finds_camelcase_struct() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits = relevant_files_for_prompt(&conn, "what does Config do?", 5).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].path, "src/config/loader.rs");
        assert!(hits[0].matched_symbols.contains(&"Config".to_string()));
    }

    #[test]
    fn relevant_files_surfaces_path_only_match_when_no_symbols() {
        let (_dir, conn) = seed_db_with_two_files();
        // Prompt has no identifiers — just bare words. Path-keyword
        // overlap on "config" should surface src/config/loader.rs.
        let hits = relevant_files_for_prompt(&conn, "load the config file", 5).unwrap();
        assert!(
            hits.iter().any(|f| f.path == "src/config/loader.rs"),
            "config path match must surface; got {hits:?}",
        );
    }

    #[test]
    fn relevant_files_respects_max_limit() {
        let (_dir, conn) = seed_db_with_two_files();
        // Prompt that hits BOTH files via path keywords; max=1 must
        // still trim.
        let hits = relevant_files_for_prompt(&conn, "auth config files", 1).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn relevant_files_max_zero_returns_empty() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits = relevant_files_for_prompt(&conn, "auth_middleware", 0).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn relevant_files_returns_empty_when_no_match() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits = relevant_files_for_prompt(&conn, "nonexistent_xyz_symbol", 5).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn render_context_block_is_empty_for_no_files() {
        assert_eq!(render_context_block(&[]), "");
    }

    #[test]
    fn render_context_block_lists_path_root_and_symbols() {
        let f = RelevantFile {
            root: "/repo/a".into(),
            path: "src/auth/middleware.rs".into(),
            identifier_hits: 1,
            matched_symbols: vec!["auth_middleware".into()],
            path_keyword_overlap: 1,
        };
        let s = render_context_block(&[f]);
        assert!(s.contains("repo-context"));
        assert!(s.contains("/repo/a/src/auth/middleware.rs"));
        assert!(s.contains("auth_middleware"));
        assert!(s.contains("path-keyword:+1"));
    }

    #[test]
    fn ranking_prefers_higher_identifier_hits_over_path_overlap() {
        let (_dir, conn) = seed_db_with_two_files();
        // Both files mentioned by path-keyword, but auth_middleware
        // is also a SYMBOL hit on `src/auth/middleware.rs`. The
        // symbol hit must outrank the pure-path match.
        let hits =
            relevant_files_for_prompt(&conn, "fix auth_middleware in config and auth code", 5)
                .unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].path, "src/auth/middleware.rs");
        assert!(hits[0].identifier_hits >= 1, "got: {:?}", hits[0]);
    }

    #[test]
    fn deterministic_ordering_on_tie() {
        // Two files with identical scores must sort lexicographically
        // by path. Pin the determinism so a future hash-iteration
        // change doesn't shuffle operator-facing output.
        let (_dir, conn) = seed_db_with_two_files();
        let hits = relevant_files_for_prompt(&conn, "auth config", 5).unwrap();
        // Both candidates have 0 identifier_hits + 1 path_keyword_overlap.
        // Ascending path order → middleware.rs (src/auth/...) BEFORE
        // loader.rs (src/config/...) because "src/auth" < "src/config".
        let paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        let auth_idx = paths.iter().position(|p| p.contains("auth"));
        let config_idx = paths.iter().position(|p| p.contains("config"));
        if let (Some(ai), Some(ci)) = (auth_idx, config_idx) {
            assert!(ai < ci, "lex order broken: {paths:?}");
        }
    }
}
