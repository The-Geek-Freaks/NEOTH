//! K-Repo-Map Phase 3b (Session 14 Pick #25) — relevance engine.
//!
//! Given a prompt and a populated `code_map.db`, return the files the
//! agent should know about when answering. The same engine powers
//! `neoth code-map relevant`, opt-in `neoth chat` `<repo-context>`
//! injection, and codegraph MCP lookups.
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
//! ## Current limits
//!
//! - Semantic similarity. The engine uses keyword matching only. It
//!   matches "fn auth_middleware" / "AuthMiddleware" / "auth_middleware"
//!   in the prompt against a symbol named `auth_middleware`; it does
//!   NOT match the prompt "how does login work" against the same
//!   symbol unless "login" / "auth" overlaps the path.
//! - Recency bias. Ranking is identifier-count + path-keyword overlap;
//!   `scanned_at` does not change rank.
//! - Cross-root deduplication. If the same symbol name appears in
//!   two persisted roots (operator scanned two repos), both files
//!   surface. The CLI shows the root so the operator can disambiguate.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use rusqlite::{Connection, Transaction};

use super::root_identity::CanonicalRepoRoot;

/// Hard budgets for untrusted prompt processing and candidate materialization.
/// Candidate queries fetch one extra row as a truncation probe.
const MAX_PROMPT_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_TERMS: usize = 64;
const MAX_PATH_KEYWORD_TERMS: usize = 64;
const MAX_TERM_BYTES: usize = 256;
const MAX_SYMBOL_CANDIDATES: usize = 200;
const MAX_PATH_CANDIDATES: usize = 200;

#[derive(Debug)]
struct TermExtraction {
    terms: Vec<String>,
    truncated: bool,
}

#[derive(Debug)]
struct RankedCandidates {
    files: Vec<RelevantFile>,
    truncated: bool,
}

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

/// Canonical root and generations observed from one SQLite snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootGenerationSnapshot {
    pub root: CanonicalRepoRoot,
    pub index_generation: i64,
    pub graph_generation: i64,
}

/// Filesystem freshness is expensive and therefore explicit at each call site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecallStaleness {
    #[default]
    Skip,
    Check,
}

/// Auditable result of one repository-local recall read transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallReceipt {
    pub snapshot: RootGenerationSnapshot,
    pub ranked_files: Vec<RelevantFile>,
    /// `None` means the caller deliberately skipped the filesystem scan.
    pub stale: Option<bool>,
    /// The result may be incomplete because an output ceiling or a bounded
    /// prompt/term/candidate work budget was exhausted.
    pub truncated: bool,
}

/// Extract identifiers from `text` using a single combined regex
/// (cached after first compile). Returns a deduplicated, case-preserving list;
/// case variants stay distinct because persisted symbol lookup is exact and
/// case-sensitive.
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
    extract_identifiers_bounded(text).terms
}

fn extract_identifiers_bounded(text: &str) -> TermExtraction {
    let (text, mut truncated) = bounded_prompt(text);
    let camel = camel_regex();
    let snake = snake_regex();
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for matched in camel.find_iter(text).chain(snake.find_iter(text)) {
        let s = matched.as_str();
        if s.len() > MAX_TERM_BYTES {
            truncated = true;
            continue;
        }
        if seen.insert(s.to_string()) {
            if out.len() == MAX_IDENTIFIER_TERMS {
                truncated = true;
                break;
            }
            out.push(s.to_string());
        }
    }
    TermExtraction {
        terms: out,
        truncated,
    }
}

fn bounded_prompt(text: &str) -> (&str, bool) {
    if text.len() <= MAX_PROMPT_BYTES {
        return (text, false);
    }
    let mut end = MAX_PROMPT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
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
    extract_path_keywords_bounded(text).terms
}

fn extract_path_keywords_bounded(text: &str) -> TermExtraction {
    let (text, mut truncated) = bounded_prompt(text);
    static CELL: OnceLock<Regex> = OnceLock::new();
    let re = CELL.get_or_init(|| Regex::new(r"[a-zA-Z][a-zA-Z0-9]{2,}").unwrap());
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in re.find_iter(text) {
        let lower = m.as_str().to_ascii_lowercase();
        if lower.len() > MAX_TERM_BYTES {
            truncated = true;
            continue;
        }
        // Filter out a tiny stop-list — bare English connectives that
        // would otherwise win every path containing the letter "f".
        if STOP_WORDS.contains(&lower.as_str()) {
            continue;
        }
        if seen.insert(lower.clone()) {
            if out.len() == MAX_PATH_KEYWORD_TERMS {
                truncated = true;
                break;
            }
            out.push(lower);
        }
    }
    TermExtraction {
        terms: out,
        truncated,
    }
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

/// Top-level engine entry: given a prompt and the caller's canonical
/// `active_root`, return up to `max_files` relevant entries from the
/// persisted code map — scoped to that one repository.
///
/// GOLD-R3-13: containment is applied BEFORE ranking and truncation. Symbol
/// hits and path scans from any other persisted root are dropped up front, so
/// a large unrelated repository can never consume the global top-k (or the
/// SQL scan cap) and hide the active repository's matches. Callers resolve the
/// active root with [`resolve_active_root`] and must NOT fall back to another
/// repository when the working directory is unmapped.
///
/// Returns an empty Vec when:
///   - `active_root` has no matching symbol/path hit in the prompt.
///   - The prompt contains no extractable identifiers AND no
///     path-keywords match any file under `active_root`.
///   - The DB has no persisted snapshots (search returns empty).
///   - `max_files == 0` (defensive — caller asked for nothing).
pub fn relevant_files_for_prompt(
    conn: &Connection,
    prompt: &str,
    active_root: &str,
    max_files: usize,
) -> Result<Vec<RelevantFile>> {
    Ok(relevant_files_for_prompt_bounded(conn, prompt, active_root, max_files)?.files)
}

fn relevant_files_for_prompt_bounded(
    conn: &Connection,
    prompt: &str,
    active_root: &str,
    max_files: usize,
) -> Result<RankedCandidates> {
    if max_files == 0 {
        return Ok(RankedCandidates {
            files: Vec::new(),
            truncated: false,
        });
    }
    let identifiers = extract_identifiers_bounded(prompt);
    let keywords = extract_path_keywords_bounded(prompt);
    let mut truncated = identifiers.truncated || keywords.truncated;
    let identifiers = identifiers.terms;
    let keywords = keywords.terms;

    // Map (root, path) → aggregated metadata. Accumulating into a
    // HashMap keeps the algorithm O(symbol_hits) instead of O(files
    // × symbols).
    let mut by_path: HashMap<(String, String), RelevantFile> = HashMap::new();

    if !identifiers.is_empty() {
        let symbol_candidates = scan_paths_by_symbols(
            conn,
            active_root,
            &identifiers,
            &keywords,
            MAX_SYMBOL_CANDIDATES,
        )?;
        truncated |= symbol_candidates.truncated;
        for hit in symbol_candidates.files {
            by_path.insert((hit.root.clone(), hit.path.clone()), hit);
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
        let path_hits = scan_paths_by_keywords(conn, active_root, &keywords, MAX_PATH_CANDIDATES)?;
        truncated |= path_hits.truncated;
        for hit in path_hits.files {
            let key = (hit.root.clone(), hit.path.clone());
            let entry = by_path.entry(key).or_insert_with(|| RelevantFile {
                root: hit.root,
                path: hit.path,
                identifier_hits: 0,
                matched_symbols: Vec::new(),
                path_keyword_overlap: hit.path_keyword_overlap,
            });
            if entry.path_keyword_overlap == 0 {
                entry.path_keyword_overlap = hit.path_keyword_overlap;
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
            // GOLD-R3-13: root is part of the deterministic tie-break. Within a
            // single active root it is constant, but keeping it here pins the
            // order should the containment invariant ever be relaxed.
            .then_with(|| a.root.cmp(&b.root))
            .then_with(|| a.path.cmp(&b.path))
    });
    if ranked.len() > max_files {
        truncated = true;
        ranked.truncate(max_files);
    }
    Ok(RankedCandidates {
        files: ranked,
        truncated,
    })
}

/// Resolve and rank one recall receipt from a single SQLite read transaction.
/// Root identity, both generations, and selected files can never come from
/// different writer commits. Filesystem staleness is computed only when the
/// caller explicitly requests it, and every canonicalization/SQLite/walk error
/// is returned rather than converted into an empty result.
pub fn recall_receipt_for_prompt(
    conn: &Connection,
    current_path: &Path,
    prompt: &str,
    max_files: usize,
    staleness: RecallStaleness,
) -> Result<Option<RecallReceipt>> {
    recall_receipt_for_prompt_with_hook(conn, current_path, prompt, max_files, staleness, || {})
}

fn recall_receipt_for_prompt_with_hook<F>(
    conn: &Connection,
    current_path: &Path,
    prompt: &str,
    max_files: usize,
    staleness: RecallStaleness,
    after_snapshot: F,
) -> Result<Option<RecallReceipt>>
where
    F: FnOnce(),
{
    let current_canonical = std::fs::canonicalize(current_path).with_context(|| {
        format!(
            "canonicalize active code-map path {}",
            current_path.display()
        )
    })?;
    let tx = conn
        .unchecked_transaction()
        .context("begin atomic code-map recall read transaction")?;
    let Some(snapshot) = resolve_active_root_snapshot_in_transaction(&tx, &current_canonical)?
    else {
        tx.commit()
            .context("commit empty code-map recall read transaction")?;
        return Ok(None);
    };
    ensure!(
        snapshot.index_generation > 0
            && snapshot.graph_generation > 0
            && snapshot.index_generation == snapshot.graph_generation,
        "code-map recall requires one complete map/graph generation; run `neoth code-map persist`"
    );
    ensure!(
        super::persist::root_snapshot_complete(&tx, snapshot.root.display())?,
        "code-map root was published from a partial scan; rebuild without explicit limits before recall"
    );
    let initial_freshness = match staleness {
        RecallStaleness::Skip => None,
        RecallStaleness::Check => Some(super::persist::index_freshness_receipt_cached(
            &tx,
            snapshot.root.display(),
            snapshot.index_generation,
        )?),
    };
    after_snapshot();
    let candidate_limit = max_files.saturating_add(1);
    let candidates =
        relevant_files_for_prompt_bounded(&tx, prompt, snapshot.root.display(), candidate_limit)?;
    let mut ranked_files = candidates.files;
    let truncated = candidates.truncated || ranked_files.len() > max_files;
    ranked_files.truncate(max_files);
    let stale = match initial_freshness {
        None => None,
        Some(initial) => {
            let final_freshness = super::persist::index_freshness_receipt_cached(
                &tx,
                snapshot.root.display(),
                snapshot.index_generation,
            )?;
            Some(
                initial.stale
                    || final_freshness.stale
                    || initial.filesystem_fingerprint != final_freshness.filesystem_fingerprint,
            )
        }
    };
    let observed_root = CanonicalRepoRoot::discover(snapshot.root.path())
        .context("re-verify physical code-map root before completing recall")?;
    ensure!(
        observed_root == snapshot.root,
        "physical code-map root was replaced during recall"
    );
    tx.commit()
        .context("commit atomic code-map recall read transaction")?;
    Ok(Some(RecallReceipt {
        snapshot,
        ranked_files,
        stale,
        truncated,
    }))
}

/// Resolve the active canonical root and generation tuple atomically.
pub fn resolve_active_root_snapshot(
    conn: &Connection,
    current_path: &Path,
) -> Result<Option<RootGenerationSnapshot>> {
    let current_canonical = std::fs::canonicalize(current_path).with_context(|| {
        format!(
            "canonicalize active code-map path {}",
            current_path.display()
        )
    })?;
    let tx = conn
        .unchecked_transaction()
        .context("begin code-map root snapshot transaction")?;
    let snapshot = resolve_active_root_snapshot_in_transaction(&tx, &current_canonical)?;
    tx.commit()
        .context("commit code-map root snapshot transaction")?;
    Ok(snapshot)
}

fn resolve_active_root_snapshot_in_transaction(
    tx: &Transaction<'_>,
    current_canonical: &Path,
) -> Result<Option<RootGenerationSnapshot>> {
    let mut stmt = tx
        .prepare(
            "SELECT root, root_identity, index_generation, graph_generation \
             FROM code_map_roots WHERE root_identity IS NOT NULL ORDER BY root ASC",
        )
        .context("prepare active code-map root snapshot query")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .context("query active code-map root snapshots")?;
    let mut candidates = Vec::new();
    for row in rows {
        let (display, identity, index_generation, graph_generation) =
            row.context("read active code-map root snapshot")?;
        if current_canonical.starts_with(Path::new(&display)) {
            candidates.push((display, identity, index_generation, graph_generation));
        }
    }
    candidates.sort_by(|a, b| {
        Path::new(&b.0)
            .components()
            .count()
            .cmp(&Path::new(&a.0).components().count())
            .then_with(|| a.0.cmp(&b.0))
    });
    let Some((display, identity, index_generation, graph_generation)) =
        candidates.into_iter().next()
    else {
        return Ok(None);
    };
    let root = CanonicalRepoRoot::from_persisted(&display, &identity)
        .with_context(|| format!("verify persisted code-map root {display:?}"))?;
    Ok(Some(RootGenerationSnapshot {
        root,
        index_generation,
        graph_generation,
    }))
}

/// GOLD-R3-13 — resolve the persisted code-map root that contains
/// `current_path`, the canonical active repository for a recall query.
///
/// Canonicalises the path, then returns the longest persisted root that is a
/// path-prefix of it. This makes containment robust to:
///   - **sub-directory prompts** — running from `<repo>/src/foo` still resolves
///     `<repo>`, because the root is a prefix (longest-match wins over any
///     shorter ancestor root).
///   - **non-canonical CWD** — a symlinked `/var` (macOS `/var`→`/private/var`),
///     an 8.3 Windows short name, or a `.` relative path all canonicalise to
///     the same absolute form the walker persisted.
///
/// Returns `None` when the path cannot be canonicalised or no persisted root
/// contains it. Callers MUST treat `None` as "no active repository" and refuse
/// to fall back to another persisted root — that cross-repo fallback is exactly
/// the leak this containment closes.
pub fn resolve_active_root(conn: &Connection, current_path: &Path) -> Option<String> {
    resolve_active_root_snapshot(conn, current_path)
        .ok()
        .flatten()
        .map(|snapshot| snapshot.root.display().to_owned())
}

/// The one persisted root, when exactly one repository is indexed.
///
/// For a caller whose working directory cannot identify a repo — a daemon runs
/// as a service, its CWD is `/` or the service directory — a single indexed root
/// is not a guess: there is no other repository the content could come from, so
/// using it cannot mix repos. With two or more roots this returns `None`, and
/// the caller must inject nothing rather than pick one.
pub fn sole_persisted_root(conn: &Connection) -> Option<String> {
    sole_persisted_root_snapshot(conn)
        .ok()
        .flatten()
        .map(|snapshot| snapshot.root.display().to_owned())
}

/// Typed, error-preserving daemon fallback. Exactly one persisted root is
/// required; legacy roots without a physical identity and multi-root stores
/// both return `None`, so the daemon never guesses.
pub fn sole_persisted_root_snapshot(conn: &Connection) -> Result<Option<RootGenerationSnapshot>> {
    let tx = conn
        .unchecked_transaction()
        .context("begin sole code-map root snapshot transaction")?;
    let rows: Vec<(String, Option<String>, i64, i64)> = {
        let mut stmt = tx
            .prepare(
                "SELECT root, root_identity, index_generation, graph_generation \
                 FROM code_map_roots ORDER BY root ASC LIMIT 2",
            )
            .context("prepare sole code-map root snapshot query")?;
        stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .context("query sole code-map root snapshot")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect sole code-map root snapshot")?
    };
    let snapshot = match rows.as_slice() {
        [(display, Some(identity), index_generation, graph_generation)] => {
            let root = CanonicalRepoRoot::from_persisted(display, identity)
                .with_context(|| format!("verify sole persisted code-map root {display:?}"))?;
            Some(RootGenerationSnapshot {
                root,
                index_generation: *index_generation,
                graph_generation: *graph_generation,
            })
        }
        _ => None,
    };
    tx.commit()
        .context("commit sole code-map root snapshot transaction")?;
    Ok(snapshot)
}

/// Root-scoped symbol candidate query. One row per file avoids materializing
/// every declaration of a common symbol. SQL ordering matches final ranking,
/// and one probe row makes the safety cap visible to the caller.
fn scan_paths_by_symbols(
    conn: &Connection,
    active_root: &str,
    identifiers: &[String],
    keywords: &[String],
    max_candidates: usize,
) -> Result<RankedCandidates> {
    if identifiers.is_empty() || max_candidates == 0 {
        return Ok(RankedCandidates {
            files: Vec::new(),
            truncated: false,
        });
    }

    let identifier_params: Vec<String> = (2..identifiers.len() + 2)
        .map(|index| format!("?{index}"))
        .collect();
    let keyword_start = identifiers.len() + 2;
    let keyword_params: Vec<String> = (keyword_start..keyword_start + keywords.len())
        .map(|index| format!("?{index}"))
        .collect();
    let path_overlap = if keyword_params.is_empty() {
        "0".to_string()
    } else {
        keyword_params
            .iter()
            .map(|param| format!("CASE WHEN LOWER(f.path) LIKE {param} THEN 1 ELSE 0 END"))
            .collect::<Vec<_>>()
            .join(" + ")
    };
    let limit_param = keyword_start + keywords.len();
    let sql = format!(
        "SELECT f.root, f.path, COUNT(DISTINCT s.name) AS identifier_hits, \
                GROUP_CONCAT(DISTINCT s.name) AS matched_symbols, \
                ({path_overlap}) AS path_overlap \
         FROM code_map_files f \
         JOIN code_map_symbols s ON s.file_id = f.id \
         WHERE f.root = ?1 AND s.name IN ({}) \
         GROUP BY f.id, f.root, f.path \
         ORDER BY identifier_hits DESC, path_overlap DESC, f.root ASC, f.path ASC \
         LIMIT ?{limit_param}",
        identifier_params.join(", ")
    );

    let mut params = Vec::with_capacity(identifiers.len() + keywords.len() + 2);
    params.push(rusqlite::types::Value::from(active_root.to_string()));
    params.extend(
        identifiers
            .iter()
            .cloned()
            .map(rusqlite::types::Value::from),
    );
    params.extend(
        keywords
            .iter()
            .map(|keyword| rusqlite::types::Value::from(format!("%{keyword}%"))),
    );
    params.push(rusqlite::types::Value::from(
        i64::try_from(max_candidates.saturating_add(1))
            .context("convert symbol candidate probe limit")?,
    ));

    let mut stmt = conn
        .prepare(&sql)
        .context("prepare bounded root-scoped symbol candidate query")?;
    let mut files: Vec<RelevantFile> = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let matched: String = row.get(3)?;
            let matched: std::collections::HashSet<&str> = matched.split(',').collect();
            Ok(RelevantFile {
                root: row.get(0)?,
                path: row.get(1)?,
                identifier_hits: row.get(2)?,
                matched_symbols: identifiers
                    .iter()
                    .filter(|identifier| matched.contains(identifier.as_str()))
                    .cloned()
                    .collect(),
                path_keyword_overlap: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect bounded root-scoped symbol candidates")?;
    let truncated = files.len() > max_candidates;
    files.truncate(max_candidates);
    Ok(RankedCandidates { files, truncated })
}

/// SQL helper — find files whose `path` contains any supplied keyword.
/// Query is root-scoped, rank-aligned, and capped with a probe row.
fn scan_paths_by_keywords(
    conn: &Connection,
    active_root: &str,
    keywords: &[String],
    max_candidates: usize,
) -> Result<RankedCandidates> {
    if keywords.is_empty() || max_candidates == 0 {
        return Ok(RankedCandidates {
            files: Vec::new(),
            truncated: false,
        });
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
    // GOLD-R3-13: containment alone is insufficient. A single large active root
    // can have >200 weak one-keyword matches that sort before the best multi-
    // keyword candidate. Compute overlap inside SQLite, rank it first, then
    // apply the bounded candidate cap with path as the deterministic tie-break.
    let root_param = keywords.len() + 1;
    let limit_param = keywords.len() + 2;
    let overlap_score = placeholders
        .iter()
        .map(|p| format!("CASE WHEN LOWER(path) LIKE {p} THEN 1 ELSE 0 END"))
        .collect::<Vec<_>>()
        .join(" + ");
    let sql = format!(
        "SELECT root, path, ({overlap_score}) AS path_overlap \
         FROM code_map_files WHERE root = ?{root_param} AND ({where_clause}) \
         ORDER BY path_overlap DESC, path ASC LIMIT ?{limit_param}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<rusqlite::types::Value> = keywords
        .iter()
        .map(|kw| rusqlite::types::Value::from(format!("%{}%", kw.to_lowercase())))
        .collect();
    params.push(rusqlite::types::Value::from(active_root.to_string()));
    params.push(rusqlite::types::Value::from(
        i64::try_from(max_candidates.saturating_add(1))
            .context("convert path candidate probe limit")?,
    ));
    let mut files: Vec<RelevantFile> = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok(RelevantFile {
                root: row.get(0)?,
                path: row.get(1)?,
                identifier_hits: 0,
                matched_symbols: Vec::new(),
                path_keyword_overlap: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let truncated = files.len() > max_candidates;
    files.truncate(max_candidates);
    Ok(RankedCandidates { files, truncated })
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
    // Persisted/imported code maps are untrusted prompt input. Filter the
    // complete rendered block so roots, paths, and symbol names cannot smuggle
    // terminal controls or credentials into a provider prompt / CCR payload.
    crate::security::redact::sanitize_tool_output(&out)
}

/// CRG-01 — render depth-1 callers of the symbols the prompt matched, so the
/// decomposer sees the structural blast radius without a grep round-trip.
/// `per_symbol_cap` bounds the lines per matched symbol; symbols are
/// deduplicated across files. Empty string when no matched symbol has a
/// caller in the graph. Same sanitize pipeline as [`render_context_block`] —
/// persisted edges are untrusted prompt input too.
pub fn render_callers_block(
    graph: &crate::code_map::graph::CallGraph,
    files: &[RelevantFile],
    per_symbol_cap: usize,
) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut lines: Vec<String> = Vec::new();
    for file in files {
        for symbol in &file.matched_symbols {
            if !seen.insert(symbol.clone()) {
                continue;
            }
            let mut callers = graph.callers_of(symbol, 1);
            callers.sort_by(|a, b| a.symbol.cmp(&b.symbol).then(a.file_path.cmp(&b.file_path)));
            callers.truncate(per_symbol_cap);
            for caller in callers {
                lines.push(format!(
                    "  - {symbol} <- {} ({})",
                    caller.symbol, caller.file_path
                ));
            }
        }
    }
    if lines.is_empty() {
        return String::new();
    }
    let mut out = String::from("# callers of matched symbols (depth 1, NEOTH code-map)\n");
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    crate::security::redact::sanitize_tool_output(&out)
}

/// Bundled architecture-improvement skill which consumes GRAPH-02 findings.
pub const ARCHITECTURE_SKILL_ID: &str = "improve_codebase_architecture";

/// Hard cap on call cycles injected into one architecture prompt. The scan is
/// local SQLite work, but the rendered result still consumes model context.
pub const ARCHITECTURE_CYCLE_LIMIT: usize = 20;
const ARCHITECTURE_EDGE_LIMIT: usize = 250_000;
const ARCHITECTURE_EDGE_TEXT_BYTE_LIMIT: usize = 32 * 1024 * 1024;

/// One cycle plus the persisted code-map root it came from. Roots stay separate
/// during detection so equal symbol names in two repositories cannot form a
/// synthetic cross-repository cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchitectureCycleFinding {
    pub root: String,
    pub symbols: Vec<String>,
}

/// Operator- and audit-facing summary of the automatic GRAPH-02 scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchitectureFindings {
    pub block: String,
    pub roots_scanned: usize,
    pub edges_scanned: usize,
    pub cycles_injected: usize,
    pub truncated: bool,
}

/// Build the architecture findings consumed by the real
/// `improve_codebase_architecture` workflow.
///
/// A non-matching skill returns `None` before touching the graph. For the
/// matching skill, only the caller-resolved current canonical repository root
/// is scanned and the resulting cycle evidence is rendered into a bounded
/// system-prompt block. An empty-but-present map still returns a block stating
/// that no cycle was found; an unknown root returns `None` rather than falling
/// back to another persisted repository.
pub fn architecture_findings_for_skill(
    conn: &Connection,
    skill_id: Option<&str>,
    root: &str,
    max_cycles: usize,
) -> Result<Option<ArchitectureFindings>> {
    if skill_id != Some(ARCHITECTURE_SKILL_ID) {
        return Ok(None);
    }

    let root_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root = ?1)",
        [root],
        |row| row.get(0),
    )?;
    if !root_exists {
        return Ok(None);
    }

    let roots_scanned = 1;
    let mut cycles: Vec<ArchitectureCycleFinding> = Vec::new();
    let mut truncated = false;

    let (edges, edge_limit_exceeded, _) =
        super::persist::load_edges_for_root_bounded_with_text_limit(
            conn,
            root,
            ARCHITECTURE_EDGE_LIMIT,
            ARCHITECTURE_EDGE_TEXT_BYTE_LIMIT,
        )?;
    if edge_limit_exceeded {
        anyhow::bail!(
            "architecture recall refused more than {ARCHITECTURE_EDGE_LIMIT} edges for one root"
        );
    }
    let edges_scanned = edges.len();
    // Ask for one extra cycle so the rendered block can disclose that the
    // context cap hid additional findings rather than pretending complete
    // coverage. `find_cycles` is deterministic over persisted edge order.
    let probe_limit = max_cycles.saturating_add(1);
    let graph = super::graph::CallGraph::from_edges(edges);
    for symbols in graph
        .find_cycles(probe_limit)
        .context("run bounded call-cycle analysis for architecture recall")?
    {
        if cycles.len() == max_cycles {
            truncated = true;
            break;
        }
        cycles.push(ArchitectureCycleFinding {
            root: root.to_string(),
            symbols,
        });
    }

    let block = render_architecture_findings(&cycles, roots_scanned, edges_scanned, truncated);
    Ok(Some(ArchitectureFindings {
        cycles_injected: cycles.len(),
        block,
        roots_scanned,
        edges_scanned,
        truncated,
    }))
}

fn render_architecture_findings(
    cycles: &[ArchitectureCycleFinding],
    roots_scanned: usize,
    edges_scanned: usize,
    truncated: bool,
) -> String {
    let mut out = format!(
        "# architecture-findings (NEOTH code-map GRAPH-02)\n\
         # Automatic persisted CallGraph cycle scan for the active architecture workflow.\n\
         # roots_scanned={roots_scanned} edges_scanned={edges_scanned} \
         cycles_injected={} truncated={truncated}\n",
        cycles.len()
    );
    if cycles.is_empty() {
        out.push_str("  - no call cycles detected in the persisted code map\n");
    } else {
        for finding in cycles {
            let mut closed = finding.symbols.clone();
            if let Some(first) = finding.symbols.first() {
                closed.push(first.clone());
            }
            out.push_str(&format!("  - {}: {}\n", finding.root, closed.join(" -> ")));
        }
        if truncated {
            out.push_str("  - additional cycles omitted by the context limit\n");
        }
    }
    crate::security::redact::sanitize_tool_output(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::graph::{CodeEdge, EdgeKind};
    use crate::code_map::persist::{
        open, persist_edges, persist_map, persist_map_and_edges, root_index_generation,
    };
    use crate::code_map::symbols::{Symbol, SymbolKind};
    use crate::code_map::walker::{Language, RepoFile, RepoMap, ScanReport};
    use tempfile::tempdir;

    /// PR5-010: a daemon's process CWD is never the indexed repo, so
    /// `resolve_active_root` always answers `None` there and the repo-map
    /// auto-context went silently dead on the channel path. One indexed root is
    /// unambiguous and may be used; two or more is a guess and must not be.
    #[test]
    fn sole_persisted_root_is_only_unambiguous_for_one_repo() {
        let dir = tempdir().unwrap();
        let mut conn = open(&dir.path().join("code_map.db")).unwrap();
        assert_eq!(
            sole_persisted_root(&conn),
            None,
            "no roots → nothing to use"
        );

        let only = dir.path().join("only");
        std::fs::create_dir(&only).unwrap();
        let only = std::fs::canonicalize(only).unwrap().display().to_string();
        persist_map(
            &mut conn,
            &RepoMap {
                root: only.clone(),
                files: Vec::new(),
                report: ScanReport::default(),
            },
        )
        .unwrap();
        assert_eq!(sole_persisted_root(&conn).as_deref(), Some(only.as_str()));

        let second = dir.path().join("second");
        std::fs::create_dir(&second).unwrap();
        let second = std::fs::canonicalize(second).unwrap().display().to_string();
        persist_map(
            &mut conn,
            &RepoMap {
                root: second,
                files: Vec::new(),
                report: ScanReport::default(),
            },
        )
        .unwrap();
        assert_eq!(
            sole_persisted_root(&conn),
            None,
            "with two repos the choice would be a guess — inject nothing"
        );
    }

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
        let hits = relevant_files_for_prompt(
            &conn,
            "where is the auth_middleware function?",
            "/repo/a",
            5,
        )
        .unwrap();
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
        let hits = relevant_files_for_prompt(&conn, "what does Config do?", "/repo/a", 5).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].path, "src/config/loader.rs");
        assert!(hits[0].matched_symbols.contains(&"Config".to_string()));
    }

    #[test]
    fn relevant_files_surfaces_path_only_match_when_no_symbols() {
        let (_dir, conn) = seed_db_with_two_files();
        // Prompt has no identifiers — just bare words. Path-keyword
        // overlap on "config" should surface src/config/loader.rs.
        let hits = relevant_files_for_prompt(&conn, "load the config file", "/repo/a", 5).unwrap();
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
        let hits = relevant_files_for_prompt(&conn, "auth config files", "/repo/a", 1).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn relevant_files_max_zero_returns_empty() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits = relevant_files_for_prompt(&conn, "auth_middleware", "/repo/a", 0).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn relevant_files_returns_empty_when_no_match() {
        let (_dir, conn) = seed_db_with_two_files();
        let hits =
            relevant_files_for_prompt(&conn, "nonexistent_xyz_symbol", "/repo/a", 5).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn active_root_containment_survives_a_larger_unrelated_repo() {
        // GOLD-R3-13 regression. Two persisted repos share a symbol name. The
        // UNRELATED repo /repo/big has 20 files that each match BOTH prompt
        // identifiers (identifier_hits = 2); the ACTIVE repo /repo/a has one
        // file matching a single identifier (identifier_hits = 1). A global
        // rank+truncate lets /repo/big consume the whole top-k and HIDE
        // /repo/a's file — the defect. With active-root containment applied
        // before ranking, the active repo's file must still surface and no
        // /repo/big row may leak.
        let dir = tempdir().unwrap();
        let path = dir.path().join("code_map.db");
        let mut conn = open(&path).unwrap();

        persist_map(
            &mut conn,
            &RepoMap {
                root: "/repo/a".into(),
                files: vec![RepoFile {
                    path: "src/auth/mod.rs".into(),
                    language: Language::Rust,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "auth_gateway".into(),
                        kind: SymbolKind::Function,
                        line: 1,
                    }],
                }],
                report: ScanReport::default(),
            },
        )
        .unwrap();

        let big_files: Vec<RepoFile> = (0..20)
            .map(|i| RepoFile {
                path: format!("src/mod_{i:02}.rs"),
                language: Language::Rust,
                bytes: 100,
                loc: 10,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![
                    Symbol {
                        name: "auth_gateway".into(),
                        kind: SymbolKind::Function,
                        line: 1,
                    },
                    Symbol {
                        name: "token_verify".into(),
                        kind: SymbolKind::Function,
                        line: 2,
                    },
                ],
            })
            .collect();
        persist_map(
            &mut conn,
            &RepoMap {
                root: "/repo/big".into(),
                files: big_files,
                report: ScanReport::default(),
            },
        )
        .unwrap();

        // Prompt names both identifiers; /repo/big files outrank on hits.
        let prompt = "where is auth_gateway and token_verify";
        let hits = relevant_files_for_prompt(&conn, prompt, "/repo/a", 3).unwrap();
        assert!(
            !hits.is_empty(),
            "active repo file must survive containment; got {hits:?}"
        );
        assert!(
            hits.iter().all(|h| h.root == "/repo/a"),
            "unrelated /repo/big leaked into active-root recall: {hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.path == "src/auth/mod.rs"),
            "active repo's matched file missing: {hits:?}"
        );

        // Sanity: scoping to /repo/big returns only big's files, never a's.
        let big = relevant_files_for_prompt(&conn, prompt, "/repo/big", 3).unwrap();
        assert!(
            !big.is_empty() && big.iter().all(|h| h.root == "/repo/big"),
            "cross-root leak in the other direction: {big:?}"
        );
    }

    #[test]
    fn same_root_path_overlap_is_ranked_before_the_candidate_cap() {
        let dir = tempdir().unwrap();
        let mut conn = open(&dir.path().join("code_map.db")).unwrap();
        let mut files: Vec<RepoFile> = (0..250)
            .map(|index| RepoFile {
                path: format!("aaa/auth/weak_{index:03}.rs"),
                language: Language::Rust,
                bytes: 1,
                loc: 1,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: Vec::new(),
            })
            .collect();
        files.push(RepoFile {
            path: "zzz/auth/config/loader.rs".into(),
            language: Language::Rust,
            bytes: 1,
            loc: 1,
            sha256: String::new(),
            mtime_ns: 0,
            symbols: Vec::new(),
        });
        persist_map(
            &mut conn,
            &RepoMap {
                root: "/repo/same-root-skew".into(),
                files,
                report: ScanReport::default(),
            },
        )
        .unwrap();

        let hits =
            relevant_files_for_prompt(&conn, "auth config loader", "/repo/same-root-skew", 1)
                .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "zzz/auth/config/loader.rs");
        assert_eq!(hits[0].path_keyword_overlap, 3);
    }

    #[test]
    fn typed_root_snapshot_resolves_subdirectories_and_dot_aliases() {
        let repo = tempdir().unwrap();
        let nested = repo.path().join("src/nested");
        std::fs::create_dir_all(&nested).unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        let root = std::fs::canonicalize(repo.path())
            .unwrap()
            .display()
            .to_string();
        persist_map(
            &mut conn,
            &RepoMap {
                root: root.clone(),
                files: Vec::new(),
                report: ScanReport::default(),
            },
        )
        .unwrap();

        let alias = nested.join("..");
        let snapshot = resolve_active_root_snapshot(&conn, &alias)
            .unwrap()
            .expect("subdirectory alias must resolve the containing root");
        assert_eq!(snapshot.root.display(), root);
        assert_eq!(snapshot.index_generation, 1);
        assert_eq!(snapshot.graph_generation, 0);
    }

    #[test]
    fn recall_receipt_rejects_unpaired_legacy_generation() {
        let repo = tempdir().unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map(&mut conn, &map).unwrap();

        let error =
            recall_receipt_for_prompt(&conn, repo.path(), "anything", 5, RecallStaleness::Skip)
                .unwrap_err();

        assert!(error.to_string().contains("complete map/graph generation"));
    }

    #[test]
    fn recall_receipt_binds_generations_and_preserves_empty_hits() {
        let repo = tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/auth.rs"), "fn auth() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map_and_edges(&mut conn, &map, &[]).unwrap();

        let receipt = recall_receipt_for_prompt(
            &conn,
            repo.path(),
            "NonexistentSymbolWithNoPathMatch",
            5,
            RecallStaleness::Check,
        )
        .unwrap()
        .expect("an indexed root returns a receipt even with zero hits");
        assert_eq!(receipt.snapshot.root.display(), map.root);
        assert_eq!(receipt.snapshot.index_generation, 1);
        assert_eq!(receipt.snapshot.graph_generation, 1);
        assert!(receipt.ranked_files.is_empty());
        assert_eq!(receipt.stale, Some(false));
        assert!(!receipt.truncated);
    }

    #[test]
    fn recall_receipt_discloses_output_truncation() {
        let repo = tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        for index in 0..202 {
            std::fs::write(
                repo.path().join(format!("src/auth_{index:03}.rs")),
                format!("fn item_{index}() {{}}\n"),
            )
            .unwrap();
        }
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map_and_edges(&mut conn, &map, &[]).unwrap();

        let receipt =
            recall_receipt_for_prompt(&conn, repo.path(), "auth", 200, RecallStaleness::Skip)
                .unwrap()
                .unwrap();

        assert_eq!(receipt.ranked_files.len(), 200);
        assert_eq!(receipt.ranked_files[0].path, "src/auth_000.rs");
        assert_eq!(receipt.ranked_files[199].path, "src/auth_199.rs");
        assert!(receipt.truncated);
    }

    #[test]
    fn recall_receipt_discloses_prompt_term_budget_exhaustion() {
        let repo = tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path())
            .unwrap()
            .display()
            .to_string();
        let files: Vec<RepoFile> = (0..80)
            .map(|index| RepoFile {
                path: format!("src/item_{index:03}.rs"),
                language: Language::Rust,
                bytes: 1,
                loc: 1,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![Symbol {
                    name: format!("term_{index:03}"),
                    kind: SymbolKind::Function,
                    line: 1,
                }],
            })
            .collect();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map_and_edges(
            &mut conn,
            &RepoMap {
                root,
                files,
                report: ScanReport::default(),
            },
            &[],
        )
        .unwrap();
        let prompt = (0..80)
            .map(|index| format!("term_{index:03}"))
            .collect::<Vec<_>>()
            .join(" ");

        let receipt =
            recall_receipt_for_prompt(&conn, repo.path(), &prompt, 100, RecallStaleness::Skip)
                .unwrap()
                .unwrap();

        assert_eq!(receipt.ranked_files.len(), MAX_IDENTIFIER_TERMS);
        assert_eq!(receipt.ranked_files[0].path, "src/item_000.rs");
        assert_eq!(receipt.ranked_files[63].path, "src/item_063.rs");
        assert!(
            receipt.truncated,
            "omitted prompt terms must make the receipt incomplete"
        );
    }

    #[test]
    fn common_symbol_candidate_cap_is_deterministic_and_disclosed() {
        let repo = tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path())
            .unwrap()
            .display()
            .to_string();
        let files: Vec<RepoFile> = (0..250)
            .map(|index| RepoFile {
                path: format!("src/duplicate_{index:03}.rs"),
                language: Language::Rust,
                bytes: 1,
                loc: 1,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![Symbol {
                    name: "shared_symbol".into(),
                    kind: SymbolKind::Function,
                    line: 1,
                }],
            })
            .collect();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map_and_edges(
            &mut conn,
            &RepoMap {
                root,
                files,
                report: ScanReport::default(),
            },
            &[],
        )
        .unwrap();

        let first = recall_receipt_for_prompt(
            &conn,
            repo.path(),
            "shared_symbol",
            MAX_SYMBOL_CANDIDATES,
            RecallStaleness::Skip,
        )
        .unwrap()
        .unwrap();
        let second = recall_receipt_for_prompt(
            &conn,
            repo.path(),
            "shared_symbol",
            MAX_SYMBOL_CANDIDATES,
            RecallStaleness::Skip,
        )
        .unwrap()
        .unwrap();

        assert_eq!(first.ranked_files, second.ranked_files);
        assert_eq!(first.ranked_files.len(), MAX_SYMBOL_CANDIDATES);
        assert_eq!(first.ranked_files[0].path, "src/duplicate_000.rs");
        assert_eq!(first.ranked_files[199].path, "src/duplicate_199.rs");
        assert!(first.truncated && second.truncated);
    }

    #[test]
    fn staleness_check_detects_edit_during_recall_query() {
        let repo = tempdir().unwrap();
        let file = repo.path().join("auth.rs");
        std::fs::write(&file, "fn auth() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map_and_edges(&mut conn, &map, &[]).unwrap();

        let receipt = recall_receipt_for_prompt_with_hook(
            &conn,
            repo.path(),
            "auth",
            5,
            RecallStaleness::Check,
            || std::fs::write(&file, "fn auth() { changed(); }\n").unwrap(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(receipt.stale, Some(true));
    }

    #[test]
    fn prompt_byte_budget_is_utf8_safe_and_explicit() {
        let prompt = format!("KnownSymbol {}TailSymbol", "é".repeat(MAX_PROMPT_BYTES));
        let extracted = extract_identifiers_bounded(&prompt);
        assert_eq!(extracted.terms, vec!["KnownSymbol"]);
        assert!(extracted.truncated);
    }

    #[test]
    fn keyword_expression_budget_is_unique_and_explicit() {
        let prompt = (0..80)
            .flat_map(|index| [format!("keyword{index:03}"), format!("keyword{index:03}")])
            .collect::<Vec<_>>()
            .join(" ");
        let extracted = extract_path_keywords_bounded(&prompt);
        let unique: std::collections::HashSet<&str> =
            extracted.terms.iter().map(String::as_str).collect();

        assert_eq!(extracted.terms.len(), MAX_PATH_KEYWORD_TERMS);
        assert_eq!(unique.len(), MAX_PATH_KEYWORD_TERMS);
        assert!(extracted.truncated);
    }

    #[test]
    fn recall_read_transaction_cannot_mix_writer_generations() {
        let repo = tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path())
            .unwrap()
            .display()
            .to_string();
        let db = tempdir().unwrap();
        let path = db.path().join("code_map.db");
        let mut setup = open(&path).unwrap();
        let make_map = |file: &str| RepoMap {
            root: root.clone(),
            files: vec![RepoFile {
                path: file.into(),
                language: Language::Rust,
                bytes: 1,
                loc: 1,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: Vec::new(),
            }],
            report: ScanReport::default(),
        };
        persist_map_and_edges(&mut setup, &make_map("old/auth.rs"), &[]).unwrap();
        let mut writer = open(&path).unwrap();

        let receipt = recall_receipt_for_prompt_with_hook(
            &setup,
            repo.path(),
            "auth",
            5,
            RecallStaleness::Skip,
            || {
                persist_map_and_edges(&mut writer, &make_map("new/auth.rs"), &[]).unwrap();
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(receipt.snapshot.index_generation, 1);
        assert_eq!(receipt.ranked_files.len(), 1);
        assert_eq!(receipt.ranked_files[0].path, "old/auth.rs");
        assert_eq!(root_index_generation(&writer, &root).unwrap(), Some(2));
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
    fn rendered_code_map_context_sanitizes_persisted_roots_paths_and_symbols() {
        let secret = concat!("sk-", "FAKE_TEST_CODE_MAP_AAAAAAAAAAAAAA");
        let colored = format!("sk-\x1b[31m{}\x1b[0m", &secret[3..]);
        let block = render_context_block(&[RelevantFile {
            root: format!("/repo/{colored}"),
            path: format!("src/useful-{colored}.rs"),
            identifier_hits: 1,
            matched_symbols: vec![format!("handler/{colored}")],
            path_keyword_overlap: 1,
        }]);

        assert!(block.contains("src/useful-"), "{block}");
        assert!(block.contains("[REDACTED:openai_key]"), "{block}");
        assert_eq!(block.matches("[REDACTED:openai_key]").count(), 3, "{block}");
        assert!(!block.contains(secret), "{block}");
        assert!(!block.contains('\x1b'), "{block:?}");
    }

    #[test]
    fn rendered_architecture_findings_sanitize_legacy_cycle_evidence() {
        let secret = concat!("sk-", "FAKE_TEST_ARCH_MAP_AAAAAAAAAAAAAA");
        let colored = format!("sk-\x1b[36m{}\x1b[0m", &secret[3..]);
        let block = render_architecture_findings(
            &[ArchitectureCycleFinding {
                root: format!("/repo/{colored}"),
                symbols: vec!["useful_a".into(), format!("useful_b/{colored}")],
            }],
            1,
            2,
            false,
        );

        assert!(block.contains("useful_a"), "{block}");
        assert!(block.contains("[REDACTED:openai_key]"), "{block}");
        assert_eq!(block.matches("[REDACTED:openai_key]").count(), 2, "{block}");
        assert!(!block.contains(secret), "{block}");
        assert!(!block.contains('\x1b'), "{block:?}");
    }

    #[test]
    fn ranking_prefers_higher_identifier_hits_over_path_overlap() {
        let (_dir, conn) = seed_db_with_two_files();
        // Both files mentioned by path-keyword, but auth_middleware
        // is also a SYMBOL hit on `src/auth/middleware.rs`. The
        // symbol hit must outrank the pure-path match.
        let hits = relevant_files_for_prompt(
            &conn,
            "fix auth_middleware in config and auth code",
            "/repo/a",
            5,
        )
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
        let hits = relevant_files_for_prompt(&conn, "auth config", "/repo/a", 5).unwrap();
        // Both candidates have 0 identifier_hits + 1 path_keyword_overlap.
        // Ascending path order → middleware.rs (src/auth/...) BEFORE
        // loader.rs (src/config/...) because "src/auth" < "src/config".
        let paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["src/auth/middleware.rs", "src/config/loader.rs"],
            "equal-score paths must have an exact deterministic order"
        );
    }

    #[test]
    fn architecture_skill_automatically_consumes_persisted_cycles() {
        let (_dir, mut conn) = seed_db_with_two_files();
        persist_edges(
            &mut conn,
            "/repo/a",
            &[
                CodeEdge {
                    from_file: "src/a.rs".into(),
                    from_symbol: "a".into(),
                    to_name: "b".into(),
                    kind: EdgeKind::Calls,
                },
                CodeEdge {
                    from_file: "src/b.rs".into(),
                    from_symbol: "b".into(),
                    to_name: "a".into(),
                    kind: EdgeKind::Calls,
                },
            ],
        )
        .unwrap();

        let findings = architecture_findings_for_skill(
            &conn,
            Some(ARCHITECTURE_SKILL_ID),
            "/repo/a",
            ARCHITECTURE_CYCLE_LIMIT,
        )
        .unwrap()
        .expect("active architecture skill must consume GRAPH-02");

        assert_eq!(findings.roots_scanned, 1);
        assert_eq!(findings.edges_scanned, 2);
        assert_eq!(findings.cycles_injected, 1);
        assert!(!findings.truncated);
        assert!(findings.block.contains("a -> b -> a"));
        assert!(findings.block.contains("architecture-findings"));
    }

    #[test]
    fn architecture_cycle_context_is_skill_scoped_and_discloses_empty_scan() {
        let (_dir, conn) = seed_db_with_two_files();
        assert!(
            architecture_findings_for_skill(&conn, Some("unrelated_skill"), "/repo/a", 20)
                .unwrap()
                .is_none(),
            "normal chat turns must not receive architecture-only graph evidence"
        );

        let findings =
            architecture_findings_for_skill(&conn, Some(ARCHITECTURE_SKILL_ID), "/repo/a", 20)
                .unwrap()
                .unwrap();
        assert_eq!(findings.cycles_injected, 0);
        assert!(findings.block.contains("no call cycles detected"));

        assert!(
            architecture_findings_for_skill(
                &conn,
                Some(ARCHITECTURE_SKILL_ID),
                "/repo/unrelated",
                20,
            )
            .unwrap()
            .is_none(),
            "an unknown/currently-unmapped repo must never fall back to another persisted root"
        );
    }

    #[test]
    fn render_callers_block_lists_deduped_capped_callers() {
        let graph = crate::code_map::graph::CallGraph::from_edges(vec![
            CodeEdge {
                from_file: "src/a.rs".into(),
                from_symbol: "alpha".into(),
                to_name: "verify_token".into(),
                kind: EdgeKind::Calls,
            },
            CodeEdge {
                from_file: "src/b.rs".into(),
                from_symbol: "beta".into(),
                to_name: "verify_token".into(),
                kind: EdgeKind::Calls,
            },
            CodeEdge {
                from_file: "src/c.rs".into(),
                from_symbol: "gamma".into(),
                to_name: "verify_token".into(),
                kind: EdgeKind::Calls,
            },
        ]);
        let files = vec![
            RelevantFile {
                root: "/repo/a".into(),
                path: "src/auth.rs".into(),
                identifier_hits: 2,
                matched_symbols: vec!["verify_token".into()],
                path_keyword_overlap: 0,
            },
            // The same symbol matched through a second file — the callers
            // section must not duplicate.
            RelevantFile {
                root: "/repo/a".into(),
                path: "src/auth2.rs".into(),
                identifier_hits: 1,
                matched_symbols: vec!["verify_token".into()],
                path_keyword_overlap: 0,
            },
        ];
        let block = render_callers_block(&graph, &files, 2);
        assert!(block.starts_with("# callers of matched symbols"));
        // Cap 2 keeps alpha+beta (sorted), drops gamma; dedupe keeps one set.
        assert_eq!(block.matches("verify_token <-").count(), 2);
        assert!(block.contains("verify_token <- alpha (src/a.rs)"));
        assert!(block.contains("verify_token <- beta (src/b.rs)"));
        assert!(!block.contains("gamma"));
    }

    #[test]
    fn render_callers_block_empty_without_matches_or_callers() {
        let graph = crate::code_map::graph::CallGraph::from_edges(Vec::new());
        assert!(render_callers_block(&graph, &[], 3).is_empty());
        let files = vec![RelevantFile {
            root: "/r".into(),
            path: "src/x.rs".into(),
            identifier_hits: 1,
            matched_symbols: vec!["lonely".into()],
            path_keyword_overlap: 0,
        }];
        assert!(
            render_callers_block(&graph, &files, 3).is_empty(),
            "a matched symbol with no callers renders nothing"
        );
    }

    #[test]
    fn render_callers_block_sanitizes_persisted_names() {
        // Persisted edges are untrusted prompt input — same posture as
        // rendered_code_map_context_sanitizes_persisted_roots_paths_and_symbols.
        let graph = crate::code_map::graph::CallGraph::from_edges(vec![CodeEdge {
            from_file: "src/\x1b[31mevil.rs".into(),
            from_symbol: "att\x07acker".into(),
            to_name: "verify_token".into(),
            kind: EdgeKind::Calls,
        }]);
        let files = vec![RelevantFile {
            root: "/r".into(),
            path: "src/auth.rs".into(),
            identifier_hits: 1,
            matched_symbols: vec!["verify_token".into()],
            path_keyword_overlap: 0,
        }];
        let block = render_callers_block(&graph, &files, 3);
        assert!(
            !block.contains('\x1b') && !block.contains('\x07'),
            "control bytes from persisted edges must never reach a provider prompt"
        );
    }
}
