//! Ctx-mode persistence — Phase 26 R-19.
//!
//! Mirrors `mcp__plugin_context-mode_context-mode__ctx_*` semantics in pure
//! Rust. No embeddings — pure FTS5 hybrid (porter BM25 → trigram → fuzzy).
//!
//! Schema (v3, see `store.rs`):
//!   - `sources` — one row per indexed document (label + metadata)
//!   - `chunks` (FTS5, porter tokenizer) — BM25 relevance search
//!   - `chunks_trigram` (FTS5, trigram tokenizer) — substring fallback
//!   - `vocabulary` — term frequencies for Levenshtein fuzzy fallback
//!
//! Public surface mirrors the ctx-mode tool names so future migration to a
//! WASM-hosted MCP plugin is mechanical.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

/// Max bytes per chunk. Synthesis tech-pin: 4 KiB. Larger sections are
/// split at paragraph boundaries before that cap.
const CHUNK_BYTE_CAP: usize = 4 * 1024;

/// One indexed document. Operator-supplied label is the unique key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRequest {
    pub label: String,
    pub content: String,
    #[serde(default)]
    pub file_path: Option<String>,
    /// "prose" / "code" / "log" / arbitrary operator tag.
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// Free-form bucket name ("docs", "tickets", "notes", …).
    #[serde(default)]
    pub source_category: Option<String>,
    /// Optional WAL event id this document corresponds to.
    #[serde(default)]
    pub event_id: Option<String>,
}

fn default_content_type() -> String {
    "prose".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexReport {
    pub label: String,
    pub source_id: i64,
    pub chunk_count: usize,
    pub bytes: usize,
    pub indexed_ts: i64,
}

/// One hit from a `search()` call. `mode` reports which fallback layer
/// produced the row so debug tooling can see what actually matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtxHit {
    pub source_id: i64,
    pub label: String,
    pub title: String,
    pub content: String,
    pub content_type: String,
    pub source_category: Option<String>,
    pub event_id: Option<String>,
    pub file_path: Option<String>,
    pub ts_ns: Option<i64>,
    pub mode: SearchMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    Bm25,
    Trigram,
    Fuzzy,
}

/// `ctx_stats` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtxStats {
    pub schema_version: i64,
    pub sources_count: i64,
    pub chunks_count: i64,
    pub vocabulary_terms: i64,
    pub latest_indexed_ts: Option<i64>,
}

/// `ctx_doctor` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtxDoctor {
    pub schema_version: i64,
    pub journal_mode: String,
    pub fts5_available: bool,
    pub trigram_tokenizer_available: bool,
}

/// Purge scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeScope<'a> {
    Source(&'a str),
    Category(&'a str),
    All,
}

// ─── Indexing ────────────────────────────────────────────────────────────

/// Index one document. Replaces any prior chunks for the same label, so
/// re-indexing is idempotent. Returns the chunk count actually written.
pub fn index_document(conn: &mut Connection, req: &IndexRequest) -> Result<IndexReport> {
    let now = now_unix();
    let content_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(req.content.as_bytes())
    );
    let tx = conn.transaction().context("begin index transaction")?;

    // Replace mode: delete existing chunks for this label, drop the old
    // sources row, insert fresh. Cheaper than a delta because we can't
    // detect which chunks changed without semantic diffing.
    delete_for_label(&tx, &req.label)?;

    tx.execute(
        "INSERT INTO sources \
         (label, content_hash, file_path, content_type, source_category, chunk_count, indexed_ts) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![
            req.label,
            content_hash,
            req.file_path,
            req.content_type,
            req.source_category,
            now,
        ],
    )?;
    let source_id = tx.last_insert_rowid();

    // Chunk + insert into both FTS tables.
    let chunks = split_chunks(&req.content);
    let mut total_bytes = 0usize;
    for (idx, chunk) in chunks.iter().enumerate() {
        total_bytes += chunk.body.len();
        for table in &["chunks", "chunks_trigram"] {
            let sql = format!(
                "INSERT INTO {table} \
                 (title, content, source_id, content_type, source_category, event_id, file_path, ts_ns) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            );
            tx.execute(
                &sql,
                params![
                    chunk.title.as_deref().unwrap_or(""),
                    chunk.body,
                    source_id,
                    req.content_type,
                    req.source_category,
                    req.event_id,
                    req.file_path,
                    now,
                ],
            )?;
        }
        bump_vocabulary(&tx, &chunk.body)?;
        let _ = idx;
    }

    tx.execute(
        "UPDATE sources SET chunk_count = ?1 WHERE id = ?2",
        params![chunks.len() as i64, source_id],
    )?;

    tx.commit().context("commit index transaction")?;

    Ok(IndexReport {
        label: req.label.clone(),
        source_id,
        chunk_count: chunks.len(),
        bytes: total_bytes,
        indexed_ts: now,
    })
}

fn delete_for_label(tx: &rusqlite::Transaction, label: &str) -> Result<()> {
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM sources WHERE label = ?1",
            params![label],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(sid) = existing {
        tx.execute("DELETE FROM chunks WHERE source_id = ?1", params![sid])?;
        tx.execute(
            "DELETE FROM chunks_trigram WHERE source_id = ?1",
            params![sid],
        )?;
        tx.execute("DELETE FROM sources WHERE id = ?1", params![sid])?;
    }
    Ok(())
}

struct Chunk {
    title: Option<String>,
    body: String,
}

/// Split content into chunks at markdown heading boundaries with a hard
/// `CHUNK_BYTE_CAP` ceiling. Oversize chunks split at paragraph (`\n\n`)
/// breaks; anything still too large gets sliced at character boundaries.
fn split_chunks(content: &str) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut current_title: Option<String> = None;
    let mut buffer = String::new();

    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('#') {
            // Heading line; flush current buffer first.
            if !buffer.trim().is_empty() {
                flush_with_caps(&mut out, current_title.clone(), &buffer);
                buffer.clear();
            }
            current_title = Some(stripped.trim_start_matches('#').trim().to_string());
            continue;
        }
        buffer.push_str(line);
        buffer.push('\n');
    }
    if !buffer.trim().is_empty() {
        flush_with_caps(&mut out, current_title, &buffer);
    }

    if out.is_empty() && !content.trim().is_empty() {
        // No headings at all: still produce at least one chunk.
        flush_with_caps(&mut out, None, content);
    }
    out
}

fn flush_with_caps(out: &mut Vec<Chunk>, title: Option<String>, body: &str) {
    if body.len() <= CHUNK_BYTE_CAP {
        out.push(Chunk {
            title,
            body: body.trim_end().to_string(),
        });
        return;
    }
    // Split at paragraph boundaries; if a single paragraph is still too big,
    // hard-slice at the byte cap on a char boundary.
    let mut current = String::new();
    for para in body.split("\n\n") {
        if current.len() + para.len() + 2 > CHUNK_BYTE_CAP && !current.is_empty() {
            out.push(Chunk {
                title: title.clone(),
                body: std::mem::take(&mut current).trim_end().to_string(),
            });
        }
        if para.len() > CHUNK_BYTE_CAP {
            for slice in hard_slice(para, CHUNK_BYTE_CAP) {
                out.push(Chunk {
                    title: title.clone(),
                    body: slice,
                });
            }
        } else {
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            current.push_str(para);
        }
    }
    if !current.trim().is_empty() {
        out.push(Chunk {
            title,
            body: current.trim_end().to_string(),
        });
    }
}

fn hard_slice(s: &str, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + cap).min(s.len());
        while end < s.len() && !s.is_char_boundary(end) {
            end -= 1;
        }
        out.push(s[start..end].to_string());
        start = end;
    }
    out
}

fn bump_vocabulary(tx: &rusqlite::Transaction, body: &str) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for raw in body.split(|c: char| !c.is_alphanumeric()) {
        let t = raw.to_lowercase();
        if t.len() < 3 || t.len() > 32 {
            continue;
        }
        if !seen.insert(t.clone()) {
            continue;
        }
        tx.execute(
            "INSERT INTO vocabulary (term, frequency) VALUES (?1, 1) \
             ON CONFLICT(term) DO UPDATE SET frequency = frequency + 1",
            params![t],
        )?;
    }
    Ok(())
}

// ─── Search ──────────────────────────────────────────────────────────────

/// Hybrid search. Tries BM25 on `chunks`; if zero rows, tries trigram; if
/// still zero, runs Levenshtein over `vocabulary` and retries BM25 with the
/// corrected query. Returns the first non-empty result set and its mode.
pub fn search(conn: &Connection, query: &str, limit: usize) -> Result<Vec<CtxHit>> {
    let query = sanitize_fts_query(query);
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }

    // 1. BM25 / porter
    let mut hits = run_match(conn, "chunks", &query, limit, SearchMode::Bm25)?;
    if !hits.is_empty() {
        return Ok(hits);
    }

    // 2. Trigram
    hits = run_match(conn, "chunks_trigram", &query, limit, SearchMode::Trigram)?;
    if !hits.is_empty() {
        return Ok(hits);
    }

    // 3. Fuzzy via vocabulary
    let corrected = fuzzy_correct(conn, &query)?;
    if corrected != query {
        let mut fuzzy = run_match(conn, "chunks", &corrected, limit, SearchMode::Fuzzy)?;
        if fuzzy.is_empty() {
            fuzzy = run_match(conn, "chunks_trigram", &corrected, limit, SearchMode::Fuzzy)?;
        }
        return Ok(fuzzy);
    }

    Ok(Vec::new())
}

fn run_match(
    conn: &Connection,
    table: &str,
    query: &str,
    limit: usize,
    mode: SearchMode,
) -> Result<Vec<CtxHit>> {
    let sql = format!(
        "SELECT t.source_id, s.label, t.title, t.content, t.content_type, \
                t.source_category, t.event_id, t.file_path, t.ts_ns \
         FROM {table} t \
         JOIN sources s ON s.id = t.source_id \
         WHERE t.content MATCH ?1 \
         ORDER BY rank \
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![query, limit as i64], |row| {
            Ok(CtxHit {
                source_id: row.get(0)?,
                label: row.get(1)?,
                title: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                content: row.get(3)?,
                content_type: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                source_category: row.get(5)?,
                event_id: row.get(6)?,
                file_path: row.get(7)?,
                ts_ns: row.get(8)?,
                mode,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// FTS5 query-string sanitiser: keep alphanumerics + space + a few operators
/// that FTS5 understands. Stops accidental injection of `"` and `*` in
/// places that would crash the parser.
fn sanitize_fts_query(q: &str) -> String {
    q.chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '-')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn fuzzy_correct(conn: &Connection, query: &str) -> Result<String> {
    let mut corrected = Vec::new();
    for word in query.split_whitespace() {
        if word.len() < 4 {
            corrected.push(word.to_string());
            continue;
        }
        let max_dist = match word.len() {
            n if n <= 6 => 1,
            n if n <= 12 => 2,
            _ => 3,
        };
        let best = nearest_vocab(conn, word, max_dist)?;
        corrected.push(best.unwrap_or_else(|| word.to_string()));
    }
    Ok(corrected.join(" "))
}

fn nearest_vocab(conn: &Connection, word: &str, max_dist: usize) -> Result<Option<String>> {
    // Vocab is small enough at v1 (<100k terms typical) for a full scan
    // bounded by length difference. A trigram index lookup is the
    // performance upgrade once vocab grows past ~500k terms.
    let lower = word.to_lowercase();
    let min_len = lower.len().saturating_sub(max_dist);
    let max_len = lower.len() + max_dist;
    let mut stmt = conn.prepare(
        "SELECT term, frequency FROM vocabulary \
         WHERE length(term) BETWEEN ?1 AND ?2",
    )?;
    let mut best: Option<(String, usize, i64)> = None;
    for row in stmt.query_map(params![min_len as i64, max_len as i64], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (term, freq) = row?;
        let dist = levenshtein(&lower, &term);
        if dist > max_dist {
            continue;
        }
        let better = match &best {
            None => true,
            Some((_, bd, bf)) => dist < *bd || (dist == *bd && freq > *bf),
        };
        if better {
            best = Some((term, dist, freq));
        }
    }
    Ok(best.map(|(t, _, _)| t))
}

/// Iterative Levenshtein. Two-row variant; O(n*m) time, O(min(n,m)) space.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (a, b) = if a.len() < b.len() { (b, a) } else { (a, b) };
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

// ─── Stats / doctor / purge ──────────────────────────────────────────────

pub fn stats(conn: &Connection) -> Result<CtxStats> {
    let schema_version: i64 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let sources_count: i64 = conn.query_row("SELECT count(*) FROM sources", [], |r| r.get(0))?;
    let chunks_count: i64 = conn.query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))?;
    let vocabulary_terms: i64 =
        conn.query_row("SELECT count(*) FROM vocabulary", [], |r| r.get(0))?;
    let latest_indexed_ts: Option<i64> = conn
        .query_row("SELECT max(indexed_ts) FROM sources", [], |r| r.get(0))
        .optional()?
        .flatten();
    Ok(CtxStats {
        schema_version,
        sources_count,
        chunks_count,
        vocabulary_terms,
        latest_indexed_ts,
    })
}

pub fn doctor(conn: &Connection) -> Result<CtxDoctor> {
    let schema_version: i64 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap_or_else(|_| "unknown".to_string());
    // FTS5 availability — we already use it; this probes the runtime build.
    let fts5_available = conn
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS __probe_fts USING fts5(x); DROP TABLE __probe_fts;",
        )
        .is_ok();
    let trigram_tokenizer_available = conn
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS __probe_tri USING fts5(x, tokenize='trigram'); DROP TABLE __probe_tri;",
        )
        .is_ok();
    Ok(CtxDoctor {
        schema_version,
        journal_mode,
        fts5_available,
        trigram_tokenizer_available,
    })
}

pub fn purge(conn: &mut Connection, scope: PurgeScope<'_>) -> Result<usize> {
    let tx = conn.transaction()?;
    let n = match scope {
        PurgeScope::Source(label) => {
            delete_for_label(&tx, label)?;
            1
        }
        PurgeScope::Category(cat) => {
            // Collect source_ids first, then bulk-delete chunks.
            let mut stmt = tx.prepare("SELECT id FROM sources WHERE source_category = ?1")?;
            let ids: Vec<i64> = stmt
                .query_map(params![cat], |r| r.get::<_, i64>(0))?
                .collect::<Result<_, _>>()?;
            drop(stmt);
            for sid in &ids {
                tx.execute("DELETE FROM chunks WHERE source_id = ?1", params![sid])?;
                tx.execute(
                    "DELETE FROM chunks_trigram WHERE source_id = ?1",
                    params![sid],
                )?;
            }
            tx.execute(
                "DELETE FROM sources WHERE source_category = ?1",
                params![cat],
            )?;
            ids.len()
        }
        PurgeScope::All => {
            let count: i64 = tx.query_row("SELECT count(*) FROM sources", [], |r| r.get(0))?;
            tx.execute("DELETE FROM chunks", [])?;
            tx.execute("DELETE FROM chunks_trigram", [])?;
            tx.execute("DELETE FROM sources", [])?;
            tx.execute("DELETE FROM vocabulary", [])?;
            count as usize
        }
    };
    tx.commit()?;
    Ok(n)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Required for `.optional()` on rusqlite query_row.
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_conn() -> Connection {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&path).expect("open");
        // Leak the tempdir for the duration of the test by Box-leaking it.
        Box::leak(Box::new(dir));
        conn
    }

    fn idx(content: &str, label: &str) -> IndexRequest {
        IndexRequest {
            label: label.to_string(),
            content: content.to_string(),
            file_path: None,
            content_type: "prose".to_string(),
            source_category: Some("test".to_string()),
            event_id: None,
        }
    }

    #[test]
    fn index_one_document_inserts_chunks_and_vocab() {
        let mut conn = fresh_conn();
        let r = index_document(
            &mut conn,
            &idx("# Title\n\nbody one\n\n# Second\n\nbody two", "doc1"),
        )
        .unwrap();
        assert_eq!(r.chunk_count, 2);
        assert!(r.bytes > 0);

        let chunks: i64 = conn
            .query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        let trig: i64 = conn
            .query_row("SELECT count(*) FROM chunks_trigram", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chunks, 2);
        assert_eq!(trig, 2);

        let vocab: i64 = conn
            .query_row("SELECT count(*) FROM vocabulary", [], |r| r.get(0))
            .unwrap();
        assert!(vocab > 0);
    }

    #[test]
    fn re_index_replaces_old_chunks_for_same_label() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("first body", "doc1")).unwrap();
        index_document(&mut conn, &idx("rewritten body", "doc1")).unwrap();

        let chunks: i64 = conn
            .query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chunks, 1, "old chunk must be replaced, not duplicated");

        // Search hits the new content, misses the old one.
        let hits = search(&conn, "rewritten", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let miss = search(&conn, "first", 10).unwrap();
        assert!(miss.is_empty());
    }

    #[test]
    fn search_bm25_finds_porter_stemmed_match() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("running quickly through testing", "doc1")).unwrap();
        let hits = search(&conn, "test", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].mode, SearchMode::Bm25);
    }

    #[test]
    fn search_falls_back_to_trigram_on_substring() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("foo barbaz qux", "doc1")).unwrap();
        // "arba" is a substring of barbaz; porter won't stem this, trigram will.
        let hits = search(&conn, "arba", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].mode, SearchMode::Trigram);
    }

    #[test]
    fn fuzzy_falls_back_when_typo() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("kubernetes deployment manifest", "doc1")).unwrap();
        // Typo "kubernates" → corrected to "kubernetes" → BM25 finds the doc.
        let hits = search(&conn, "kubernates", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].mode, SearchMode::Fuzzy);
    }

    #[test]
    fn search_returns_empty_on_no_match_or_blank() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("some content", "doc1")).unwrap();
        assert!(search(&conn, "", 10).unwrap().is_empty());
        assert!(
            search(&conn, "completelyunrelatedxyzword", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn stats_reports_chunk_and_source_counts() {
        let mut conn = fresh_conn();
        // Use real words (>=3 chars) so the vocabulary table picks them up.
        index_document(&mut conn, &idx("alpha beta gamma", "one")).unwrap();
        index_document(&mut conn, &idx("delta epsilon zeta", "two")).unwrap();
        let s = stats(&conn).unwrap();
        assert_eq!(s.sources_count, 2);
        assert_eq!(s.chunks_count, 2);
        assert!(s.vocabulary_terms > 0);
        assert!(s.latest_indexed_ts.is_some());
    }

    #[test]
    fn doctor_reports_fts5_available_and_wal_mode() {
        let conn = fresh_conn();
        let d = doctor(&conn).unwrap();
        assert!(d.fts5_available);
        assert!(d.trigram_tokenizer_available);
        // `journal_mode` is wal but case can vary.
        assert!(d.journal_mode.to_lowercase().contains("wal"));
    }

    #[test]
    fn purge_source_deletes_one() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("keep this", "keep")).unwrap();
        index_document(&mut conn, &idx("drop this", "drop")).unwrap();
        let n = purge(&mut conn, PurgeScope::Source("drop")).unwrap();
        assert_eq!(n, 1);
        let chunks: i64 = conn
            .query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chunks, 1);
    }

    #[test]
    fn purge_all_wipes_everything() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("a", "x")).unwrap();
        index_document(&mut conn, &idx("b", "y")).unwrap();
        let n = purge(&mut conn, PurgeScope::All).unwrap();
        assert_eq!(n, 2);
        let chunks: i64 = conn
            .query_row("SELECT count(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chunks, 0);
        let vocab: i64 = conn
            .query_row("SELECT count(*) FROM vocabulary", [], |r| r.get(0))
            .unwrap();
        assert_eq!(vocab, 0);
    }

    #[test]
    fn levenshtein_basic_cases() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("identical", "identical"), 0);
    }

    #[test]
    fn split_chunks_respects_headings_and_cap() {
        let body = "# Heading 1\n\nbody one\n\n# Heading 2\n\nbody two";
        let chunks = split_chunks(body);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].title.as_deref(), Some("Heading 1"));
        assert_eq!(chunks[1].title.as_deref(), Some("Heading 2"));
    }
}
