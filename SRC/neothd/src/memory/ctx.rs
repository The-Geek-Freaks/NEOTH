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

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use super::document_provenance::DocumentProvenance;

pub mod logical;
mod logical_request;

/// Max bytes per chunk. Synthesis tech-pin: 4 KiB. Larger sections are
/// split at paragraph boundaries before that cap.
const CHUNK_BYTE_CAP: usize = 4 * 1024;
/// Count the actual stored structure JSON once per returned chunk, including
/// repeated hits from one source. Overflow is an error, never partial success.
const MAX_SEARCH_STRUCTURE_BYTES: usize = 1024 * 1024;

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
    /// Describes the complete extracted source text, not an individual chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_provenance: Option<DocumentProvenance>,
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
    /// Provenance of the full source text from which this hit was chunked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_document_provenance: Option<DocumentProvenance>,
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
    let tx = conn.transaction().context("begin index transaction")?;
    logical::refuse_legacy_replacement(&tx, &req.label)?;
    let report = index_document_in_transaction(&tx, req)?;
    tx.commit().context("commit index transaction")?;
    Ok(report)
}

fn index_document_in_transaction(tx: &rusqlite::Transaction<'_>, req: &IndexRequest) -> Result<IndexReport> {
    let provenance = req.document_provenance.as_ref();
    if let Some(provenance) = provenance {
        provenance.validate_for_content(&req.content)?;
    }
    let source_bytes = provenance
        .map(|value| i64::try_from(value.source_bytes))
        .transpose()
        .context("document source byte count cannot be stored")?;
    let text_bytes = provenance
        .map(|value| i64::try_from(value.extracted_text_bytes))
        .transpose()
        .context("document text byte count cannot be stored")?;
    let structure_json = provenance
        .and_then(|value| value.structure.as_ref())
        .map(super::document_structure::DocumentStructure::to_json)
        .transpose()?;
    let now = now_unix();
    let content_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(req.content.as_bytes())
    );
    // Replace mode: delete existing chunks for this label, drop the old
    // sources row, insert fresh. Cheaper than a delta because we can't
    // detect which chunks changed without semantic diffing.
    delete_for_label(tx, &req.label)?;

    tx.execute(
        "INSERT INTO sources \
         (label, content_hash, file_path, content_type, source_category, chunk_count, indexed_ts, \
          document_provenance_schema, document_parser_version, document_source_sha256, \
          document_source_bytes, document_text_sha256, document_text_bytes, \
          document_text_encoding, document_text_truncated, document_structure_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            req.label,
            content_hash,
            req.file_path,
            req.content_type,
            req.source_category,
            now,
            provenance.map(|value| value.schema.as_str()),
            provenance.map(|value| value.parser_version.as_str()),
            provenance.map(|value| value.source_bytes_sha256.as_str()),
            source_bytes,
            provenance.map(|value| value.extracted_text_sha256.as_str()),
            text_bytes,
            provenance.map(|value| value.extracted_text_encoding.as_str()),
            provenance.map(|value| i64::from(value.extracted_text_truncated)),
            structure_json,
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
        bump_vocabulary(tx, &chunk.body)?;
        let _ = idx;
    }

    tx.execute(
        "UPDATE sources SET chunk_count = ?1 WHERE id = ?2",
        params![chunks.len() as i64, source_id],
    )?;

    Ok(IndexReport {
        label: req.label.clone(),
        source_id,
        chunk_count: chunks.len(),
        bytes: total_bytes,
        indexed_ts: now,
    })
}

fn delete_for_label(tx: &rusqlite::Transaction, label: &str) -> Result<usize> {
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM sources WHERE label = ?1",
            params![label],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(sid) = existing {
        remove_source_vocabulary(tx, sid)?;
        tx.execute("DELETE FROM chunks WHERE source_id = ?1", params![sid])?;
        tx.execute(
            "DELETE FROM chunks_trigram WHERE source_id = ?1",
            params![sid],
        )?;
        Ok(tx.execute("DELETE FROM sources WHERE id = ?1", params![sid])?)
    } else {
        Ok(0)
    }
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
        let end = char_boundary_truncate(&s[start..], cap);
        out.push(s[start..start + end].to_string());
        start += end;
        if end == 0 {
            break; // guard against infinite loop on malformed input
        }
    }
    out
}

// ─── Format-before-truncate (GOLD-ADAPT-SPEAKR-03) ───────────────────────

/// A single timed segment from a transcript (speaker + text + optional
/// start-time in seconds). Used by [`segments_to_plain_text`].
#[derive(Debug, Clone)]
pub struct TranscriptSegment {
    /// Speaker label, e.g. `"SPEAKER_00"` or a resolved name.
    pub speaker: String,
    /// The spoken text. May contain multi-byte Unicode.
    pub text: String,
    /// Optional wall-clock offset in seconds from transcript start.
    pub start_s: Option<f64>,
}

/// Format a slice of [`TranscriptSegment`]s into a single plain-text string
/// suitable for passing to an LLM prompt.
///
/// Layout per segment:
/// ```text
/// [00:01:23] SPEAKER: text here
/// ```
/// The timestamp column is omitted when `start_s` is `None`. Segments with
/// empty (whitespace-only) text are skipped.
///
/// **This function must be called BEFORE any byte-level truncation** so that
/// Unicode characters are never split mid-sequence. Pass the returned `String`
/// to [`truncate_to_char_boundary`] when you need to cap the byte length.
pub fn segments_to_plain_text(segments: &[TranscriptSegment]) -> String {
    let mut out = String::new();
    for seg in segments {
        let trimmed = seg.text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(s) = seg.start_s {
            let total_secs = s as u64;
            let h = total_secs / 3600;
            let m = (total_secs % 3600) / 60;
            let secs = total_secs % 60;
            out.push_str(&format!("[{h:02}:{m:02}:{secs:02}] "));
        }
        out.push_str(&seg.speaker);
        out.push_str(": ");
        out.push_str(trimmed);
        out.push('\n');
    }
    out
}

/// Truncate `s` to at most `cap` **bytes** while guaranteeing the result ends
/// on a valid UTF-8 character boundary.
///
/// Returns the truncated string. If `s.len() <= cap` the original content is
/// returned unchanged (no allocation beyond the `String` conversion).
///
/// # Panics
/// Never: `is_char_boundary` contracts guarantee we never slice into a
/// multi-byte sequence.
pub fn truncate_to_char_boundary(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let safe = char_boundary_truncate(s, cap);
    &s[..safe]
}

/// Return the largest byte index `i <= cap` such that `s[..i]` is a valid
/// UTF-8 string. If `cap >= s.len()` returns `s.len()`.
fn char_boundary_truncate(s: &str, cap: usize) -> usize {
    let end = cap.min(s.len());
    // Walk back from `end` until we land on a char boundary.
    let mut i = end;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn vocabulary_terms(body: &str) -> impl Iterator<Item = String> + '_ {
    let mut seen = std::collections::HashSet::new();
    body.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(move |term| (3..=32).contains(&term.len()) && seen.insert(term.clone()))
}

fn bump_vocabulary(conn: &Connection, body: &str) -> Result<()> {
    for term in vocabulary_terms(body) {
        let changed = conn.execute(
            "INSERT INTO vocabulary (term, frequency) VALUES (?1, 1) \
             ON CONFLICT(term) DO UPDATE SET frequency = frequency + 1 \
             WHERE typeof(frequency) = 'integer' AND frequency BETWEEN 1 AND 9223372036854775806",
            params![term],
        )?;
        ensure!(
            changed == 1,
            "ctx vocabulary frequency is invalid or exhausted"
        );
    }
    Ok(())
}

fn remove_source_vocabulary(tx: &rusqlite::Transaction, source_id: i64) -> Result<()> {
    // Canonical chunks own the exact prior bodies. The trigram mirror must
    // never contribute a second count. Keep subtraction in the caller's tx.
    let mut statement = tx.prepare("SELECT content FROM chunks WHERE source_id = ?1")?;
    let mut rows = statement.query([source_id])?;
    while let Some(row) = rows.next()? {
        let body: String = row.get(0)?;
        for term in vocabulary_terms(&body) {
            // Delete 1 first: decrementing 2 before this DELETE would erase
            // the surviving chunk's contribution as well.
            if tx.execute(
                "DELETE FROM vocabulary WHERE term = ?1 AND typeof(frequency) = 'integer' AND frequency = 1",
                [&term],
            )? == 0
            {
                let changed = tx.execute(
                    "UPDATE vocabulary SET frequency = frequency - 1 \
                     WHERE term = ?1 AND typeof(frequency) = 'integer' AND frequency > 1",
                    [&term],
                )?;
                ensure!(changed == 1, "ctx vocabulary contribution is missing or invalid");
            }
        }
    }
    Ok(())
}

/// Repair historical replacement/purge drift once during schema migration.
/// The migration dispatcher owns both rollback and the schema-version stamp.
pub(super) fn rebuild_vocabulary(conn: &Connection) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "ctx vocabulary rebuild requires a transaction"
    );
    conn.execute("DELETE FROM vocabulary", [])?;
    let mut statement = conn.prepare("SELECT content FROM chunks ORDER BY rowid")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let body: String = row.get(0)?;
        bump_vocabulary(conn, &body)?;
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
    let sql_limit =
        i64::try_from(limit).context("ctx search limit exceeds SQLite integer range")?;
    let sql = format!(
        "SELECT t.source_id, s.label, t.title, t.content, t.content_type, \
                t.source_category, t.event_id, t.file_path, t.ts_ns, \
                s.document_provenance_schema, s.document_parser_version, s.document_source_sha256, \
                s.document_source_bytes, s.document_text_sha256, s.document_text_bytes, \
                s.document_text_encoding, s.document_text_truncated, s.document_structure_json \
         FROM {table} t \
         JOIN sources s ON s.id = t.source_id \
         WHERE t.content MATCH ?1 \
         ORDER BY rank \
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut structure_bytes = 0usize;
    let rows = stmt
        .query_map(params![query, sql_limit], |row| {
            let source_document_provenance = DocumentProvenance::from_row(row, 9)?;
            if let rusqlite::types::ValueRef::Text(bytes) = row.get_ref(17)? {
                structure_bytes = structure_bytes
                    .checked_add(bytes.len())
                    .filter(|total| *total <= MAX_SEARCH_STRUCTURE_BYTES)
                    .ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            17,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::other(
                                "ctx search structure payload limit exceeded",
                            )),
                        )
                    })?;
            }
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
                source_document_provenance,
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
            let source: Option<i64> = tx.query_row(
                "SELECT id FROM sources WHERE label=?1", [label], |row| row.get(0),
            ).optional()?;
            if let Some(source) = source {
                logical::remove_owner_for_source(&tx, source)?;
            }
            delete_for_label(&tx, label)?
        }
        PurgeScope::Category(cat) => {
            // Collect source_ids first, then bulk-delete chunks.
            let mut stmt = tx.prepare("SELECT id FROM sources WHERE source_category = ?1")?;
            let ids: Vec<i64> = stmt
                .query_map(params![cat], |r| r.get::<_, i64>(0))?
                .collect::<Result<_, _>>()?;
            drop(stmt);
            for sid in &ids {
                logical::remove_owner_for_source(&tx, *sid)?;
                remove_source_vocabulary(&tx, *sid)?;
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
            tx.execute("DELETE FROM logical_documents", [])?;
            tx.execute("DELETE FROM chunks", [])?;
            tx.execute("DELETE FROM chunks_trigram", [])?;
            tx.execute("DELETE FROM sources", [])?;
            tx.execute("DELETE FROM vocabulary", [])?;
            count as usize
        }
    };
    logical::advance_after_purge(&tx, n)?;
    tx.commit()?;
    Ok(n)
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
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
            document_provenance: None,
        }
    }

    fn proven_document(content: &str, label: &str) -> IndexRequest {
        use sha2::{Digest, Sha256};
        let mut request = idx(content, label);
        request.document_provenance = Some(DocumentProvenance {
            schema: "neoth.document-provenance.v1".into(),
            parser_version: "document-extractor/v1".into(),
            source_bytes_sha256: "a".repeat(64),
            source_bytes: 100,
            extracted_text_sha256: hex::encode(Sha256::digest(content.as_bytes())),
            extracted_text_bytes: content.len() as u64,
            extracted_text_encoding: "utf-8".into(),
            extracted_text_truncated: true,
            structure: None,
        });
        request
    }

    fn structured_document(content: &str, label: &str) -> IndexRequest {
        let mut request = proven_document(content, label);
        let provenance = request.document_provenance.as_mut().unwrap();
        provenance.structure = Some(
            super::super::document_structure::DocumentStructure::from_value(
                &super::super::document_structure::test_structure_value(
                    &provenance.source_bytes_sha256,
                    provenance.source_bytes,
                ),
            )
            .unwrap(),
        );
        request
    }

    #[test]
    fn document_structure_survives_reopen_and_all_search_modes_as_source_ranges() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&path).unwrap();
        let request = structured_document("running quickly testing barbaz kubernetes", "doc");
        index_document(&mut conn, &request).unwrap();
        drop(conn);
        let conn = crate::memory::store::open(&path).unwrap();
        for (query, mode) in [
            ("test", SearchMode::Bm25),
            ("arba", SearchMode::Trigram),
            ("kubernates", SearchMode::Fuzzy),
        ] {
            let hits = search(&conn, query, 10).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].mode, mode);
            assert_eq!(
                hits[0].source_document_provenance,
                request.document_provenance
            );
            assert_eq!(
                serde_json::to_value(&hits[0]).unwrap()["source_document_provenance"]["structure"]
                    ["coordinate_system"],
                "zip-entry-utf8-byte-offset/v1"
            );
        }
    }

    #[test]
    fn structure_replacement_failure_and_purge_follow_the_existing_source_transaction() {
        let mut conn = fresh_conn();
        let original = structured_document("original retained text", "doc");
        index_document(&mut conn, &original).unwrap();
        let mut invalid = structured_document("replacement text", "doc");
        invalid.document_provenance.as_mut().unwrap().source_bytes += 1;
        assert!(index_document(&mut conn, &invalid).is_err());
        conn.execute_batch(
            "CREATE TRIGGER reject_structure_replacement AFTER INSERT ON sources
            BEGIN SELECT RAISE(ABORT, 'injected source failure'); END;",
        )
        .unwrap();
        assert!(
            index_document(&mut conn, &structured_document("replacement text", "doc")).is_err()
        );
        assert_eq!(
            search(&conn, "original", 10).unwrap()[0].source_document_provenance,
            original.document_provenance
        );
        conn.execute_batch("DROP TRIGGER reject_structure_replacement")
            .unwrap();
        index_document(&mut conn, &proven_document("replacement text", "doc")).unwrap();
        let hits = search(&conn, "replacement", 10).unwrap();
        assert!(
            hits[0]
                .source_document_provenance
                .as_ref()
                .unwrap()
                .structure
                .is_none()
        );
        let cleared: bool = conn
            .query_row(
                "SELECT document_structure_json IS NULL FROM sources WHERE label='doc'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(cleared);
        index_document(&mut conn, &original).unwrap();
        assert_eq!(purge(&mut conn, PurgeScope::Source("doc")).unwrap(), 1);
        assert!(search(&conn, "original", 10).unwrap().is_empty());
        let remaining: i64 = conn
            .query_row(
                "SELECT count(*) FROM sources WHERE document_structure_json IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
        for scope in [PurgeScope::Category("test"), PurgeScope::All] {
            index_document(&mut conn, &original).unwrap();
            assert_eq!(purge(&mut conn, scope).unwrap(), 1);
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sources WHERE document_structure_json IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn corrupt_or_orphaned_persisted_structure_never_becomes_an_unbound_hit() {
        let mut conn = fresh_conn();
        let request = structured_document("find this document", "doc");
        for malformed in [
            "{".to_owned(),
            "null".to_owned(),
            " ".repeat(super::super::document_structure::MAX_STRUCTURE_JSON_BYTES + 1),
        ] {
            index_document(&mut conn, &request).unwrap();
            conn.execute(
                "UPDATE sources SET document_structure_json=?1",
                params![malformed],
            )
            .unwrap();
            assert!(search(&conn, "document", 10).is_err());
        }
        index_document(&mut conn, &request).unwrap();
        conn.execute(
            "UPDATE sources SET document_source_sha256=?1",
            params!["c".repeat(64)],
        )
        .unwrap();
        assert!(search(&conn, "document", 10).is_err());
        index_document(&mut conn, &idx("find this document", "legacy")).unwrap();
        purge(&mut conn, PurgeScope::Source("doc")).unwrap();
        let sidecar = request
            .document_provenance
            .unwrap()
            .structure
            .unwrap()
            .to_json()
            .unwrap();
        conn.execute(
            "UPDATE sources SET document_structure_json=?1 WHERE label='legacy'",
            params![sidecar],
        )
        .unwrap();
        assert!(search(&conn, "document", 10).is_err());
    }

    #[test]
    fn v48_store_reopens_with_nullable_structure_and_preserved_existing_provenance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&path).unwrap();
        let request = proven_document("retained provenance", "doc");
        index_document(&mut conn, &request).unwrap();
        index_document(&mut conn, &idx("unbound legacy", "legacy")).unwrap();
        logical::remove_schema_for_legacy_fixture(&conn).unwrap();
        conn.execute_batch(
            "ALTER TABLE sources DROP COLUMN document_structure_json;
            UPDATE meta SET value='48' WHERE key='schema_version';",
        )
        .unwrap();
        drop(conn);
        let mut conn = crate::memory::store::open(&path).unwrap();
        assert_eq!(
            crate::memory::migrations::current_version(&conn).unwrap(),
            crate::memory::store::SCHEMA_VERSION
        );
        assert_eq!(
            search(&conn, "provenance", 10).unwrap()[0].source_document_provenance,
            request.document_provenance
        );
        assert!(
            search(&conn, "legacy", 10).unwrap()[0]
                .source_document_provenance
                .is_none()
        );
        let upgraded = structured_document("retained provenance", "doc");
        index_document(&mut conn, &upgraded).unwrap();
        drop(conn);
        let conn = crate::memory::store::open(&path).unwrap();
        assert_eq!(
            search(&conn, "provenance", 10).unwrap()[0].source_document_provenance,
            upgraded.document_provenance
        );
    }

    #[test]
    fn repeated_source_structure_counts_against_the_search_payload_budget() {
        let mut value =
            super::super::document_structure::test_structure_value(&"a".repeat(64), 100);
        value["entry_bytes"] = serde_json::json!(8_000_000);
        value["tables"][0]["source_range"] = serde_json::json!([1, 7_999_999]);
        value["tables"][0]["rows"][0]["source_range"] = serde_json::json!([2, 7_999_998]);
        value["tables"][0]["rows"][0]["cells"] = serde_json::json!([{
            "source_range": [3, 7_999_997],
            "paragraph_source_ranges": (0..4_096u64).map(|i| [1_000_000+i*10, 1_000_005+i*10]).collect::<Vec<_>>()
        }]);
        let structure =
            super::super::document_structure::DocumentStructure::from_value(&value).unwrap();
        let structure_len = structure.to_json().unwrap().len();
        let allowed = MAX_SEARCH_STRUCTURE_BYTES / structure_len;
        let paragraph = format!("needle {}\n\n", "x".repeat(CHUNK_BYTE_CAP - 32));
        let mut request = proven_document(&paragraph.repeat(allowed + 2), "doc");
        request.document_provenance.as_mut().unwrap().structure = Some(structure);
        let mut conn = fresh_conn();
        index_document(&mut conn, &request).unwrap();
        assert_eq!(search(&conn, "needle", allowed).unwrap().len(), allowed);
        let error = search(&conn, "needle", allowed + 1).unwrap_err();
        assert!(format!("{error:#}").contains("structure payload limit"));
        assert_eq!(search(&conn, "needle", 1).unwrap().len(), 1);
        if usize::BITS > 63 {
            let empty = Connection::open_in_memory().unwrap();
            let error =
                run_match(&empty, "chunks", "needle", usize::MAX, SearchMode::Bm25).unwrap_err();
            assert!(format!("{error:#}").contains("SQLite integer range"));
        }
    }

    #[test]
    fn document_provenance_survives_reopen_and_all_search_fallbacks_without_merging_labels() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&path).unwrap();
        let request = proven_document("running quickly testing barbaz kubernetes", "first");
        let first = index_document(&mut conn, &request).unwrap();
        let mut second = request.clone();
        second.label = "same-bytes-distinct-document".into();
        let second = index_document(&mut conn, &second).unwrap();
        assert_ne!(first.source_id, second.source_id);
        drop(conn);
        let conn = crate::memory::store::open(&path).unwrap();
        for (query, mode) in [
            ("test", SearchMode::Bm25),
            ("arba", SearchMode::Trigram),
            ("kubernates", SearchMode::Fuzzy),
        ] {
            let hits = search(&conn, query, 10).unwrap();
            assert_eq!(hits.len(), 2, "{query}");
            for hit in hits {
                assert_eq!(hit.mode, mode);
                assert_eq!(hit.source_document_provenance, request.document_provenance);
                assert_eq!(
                    serde_json::to_value(&hit).unwrap()["source_document_provenance"]["extracted_text_truncated"],
                    true,
                );
            }
        }
    }

    #[test]
    fn upgraded_v46_store_indexes_provenance_and_reopens_with_legacy_rows_intact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let mut conn = crate::memory::store::open(&path).unwrap();
        let legacy = index_document(&mut conn, &idx("legacy retained body", "legacy")).unwrap();
        logical::remove_schema_for_legacy_fixture(&conn).unwrap();
        // Reconstruct the exact v46 sources columns. All other schema objects
        // are unchanged by v47; the existing legacy FTS rows remain in place.
        for column in [
            "document_provenance_schema",
            "document_parser_version",
            "document_source_sha256",
            "document_source_bytes",
            "document_text_sha256",
            "document_text_bytes",
            "document_text_encoding",
            "document_text_truncated",
            "document_structure_json",
        ] {
            conn.execute_batch(&format!("ALTER TABLE sources DROP COLUMN {column};"))
                .unwrap();
        }
        conn.execute(
            "UPDATE meta SET value = '46' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
        drop(conn);
        let mut migrated = crate::memory::store::open(&path).unwrap();
        assert_eq!(
            crate::memory::migrations::current_version(&migrated).unwrap(),
            crate::memory::store::SCHEMA_VERSION
        );
        let request = proven_document("new searchable document", "document");
        index_document(&mut migrated, &request).unwrap();
        drop(migrated);
        let reopened = crate::memory::store::open(&path).unwrap();
        let legacy_hits = search(&reopened, "legacy", 10).unwrap();
        assert_eq!(legacy_hits.len(), 1);
        assert_eq!(legacy_hits[0].source_id, legacy.source_id);
        assert!(legacy_hits[0].source_document_provenance.is_none());
        let hits = search(&reopened, "searchable", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].source_document_provenance,
            request.document_provenance
        );
    }
    #[test]
    fn invalid_document_provenance_and_aborted_replacement_preserve_source_and_both_indexes() {
        let mut conn = fresh_conn();
        let request = proven_document("original retained body", "doc");
        let original = index_document(&mut conn, &request).unwrap();
        let mut invalid = proven_document("replacement body", "doc");
        invalid
            .document_provenance
            .as_mut()
            .unwrap()
            .extracted_text_sha256 = "b".repeat(64);
        assert!(index_document(&mut conn, &invalid).is_err());
        conn.execute_batch(
            "CREATE TRIGGER reject_document_replacement AFTER INSERT ON sources
             BEGIN SELECT RAISE(ABORT, 'injected replacement failure'); END;",
        )
        .unwrap();
        assert!(index_document(&mut conn, &proven_document("replacement body", "doc")).is_err());
        let hits = search(&conn, "original", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source_id, original.source_id);
        assert_eq!(
            hits[0].source_document_provenance,
            request.document_provenance
        );
        for table in ["chunks", "chunks_trigram"] {
            let retained: (i64, String) = conn
                .query_row(
                    &format!("SELECT source_id, content FROM {table}"),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(retained, (original.source_id, request.content.clone()));
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn replacing_document_with_unbound_text_clears_provenance_without_reusing_old_receipt() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &proven_document("original body", "doc")).unwrap();
        index_document(&mut conn, &idx("replacement body", "doc")).unwrap();
        let hits = search(&conn, "replacement", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].source_document_provenance.is_none());
        assert!(
            serde_json::to_value(&hits[0])
                .unwrap()
                .get("source_document_provenance")
                .is_none()
        );
        let unbound: bool = conn
            .query_row(
                "SELECT document_provenance_schema IS NULL AND document_parser_version IS NULL
                 AND document_source_sha256 IS NULL AND document_source_bytes IS NULL
                 AND document_text_sha256 IS NULL AND document_text_bytes IS NULL
                 AND document_text_encoding IS NULL AND document_text_truncated IS NULL
                 AND document_structure_json IS NULL
             FROM sources WHERE label = 'doc'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(unbound);
    }

    #[test]
    fn search_rejects_partial_or_corrupt_document_provenance_instead_of_hiding_it() {
        let mut conn = fresh_conn();
        for mutation in [
            "document_parser_version = NULL",
            "document_source_bytes = -1",
            "document_text_bytes = 8388609",
            "document_source_sha256 = 'bad'",
            "document_text_truncated = 2",
            "document_provenance_schema = 'future'",
        ] {
            index_document(&mut conn, &proven_document("original body", "doc")).unwrap();
            conn.execute(
                &format!("UPDATE sources SET {mutation} WHERE label = 'doc'"),
                [],
            )
            .unwrap();
            assert!(search(&conn, "original", 10).is_err(), "{mutation}");
        }
    }

    fn vocabulary_snapshot(conn: &Connection) -> Vec<(String, i64)> {
        conn.prepare("SELECT term, frequency FROM vocabulary ORDER BY term")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn index_snapshot(conn: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        ["sources", "chunks", "chunks_trigram", "vocabulary"]
            .into_iter()
            .map(|table| {
                let mut statement = conn
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns).map(|column| row.get(column)).collect()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn vocabulary_replacement_and_source_purge_preserve_per_chunk_counts() {
        let mut conn = fresh_conn();
        index_document(
            &mut conn,
            &idx(
                "# One\nshared shared amber\n# Two\nshared cobalt",
                "replace",
            ),
        )
        .unwrap();
        index_document(&mut conn, &idx("shared retained", "keep")).unwrap();
        assert_eq!(
            vocabulary_snapshot(&conn),
            vec![
                ("amber".into(), 1),
                ("cobalt".into(), 1),
                ("retained".into(), 1),
                ("shared".into(), 3),
            ]
        );
        for _ in 0..2 {
            index_document(&mut conn, &idx("shared newword newword", "replace")).unwrap();
            assert_eq!(
                vocabulary_snapshot(&conn),
                vec![
                    ("newword".into(), 1),
                    ("retained".into(), 1),
                    ("shared".into(), 2),
                ]
            );
        }
        assert_eq!(purge(&mut conn, PurgeScope::Source("replace")).unwrap(), 1);
        assert_eq!(purge(&mut conn, PurgeScope::Source("replace")).unwrap(), 0);
        assert_eq!(
            vocabulary_snapshot(&conn),
            vec![("retained".into(), 1), ("shared".into(), 1)]
        );
        assert_eq!(search(&conn, "shard", 5).unwrap()[0].label, "keep");
        assert_eq!(purge(&mut conn, PurgeScope::All).unwrap(), 1);
        for table in index_snapshot(&conn) {
            assert!(table.is_empty());
        }
    }

    #[test]
    fn vocabulary_category_purge_retains_only_surviving_chunk_terms() {
        let mut conn = fresh_conn();
        index_document(&mut conn, &idx("shared amber", "drop-one")).unwrap();
        index_document(&mut conn, &idx("shared cobalt", "drop-two")).unwrap();
        let mut keep = idx("shared retained", "keep");
        keep.source_category = Some("other".into());
        index_document(&mut conn, &keep).unwrap();
        assert_eq!(purge(&mut conn, PurgeScope::Category("test")).unwrap(), 2);
        assert_eq!(
            vocabulary_snapshot(&conn),
            vec![("retained".into(), 1), ("shared".into(), 1)]
        );
        assert_eq!(purge(&mut conn, PurgeScope::Category("test")).unwrap(), 0);
        for table in ["sources", "chunks", "chunks_trigram"] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn vocabulary_corruption_aborts_replacement_and_purges_atomically() {
        for mutation in [
            "DELETE FROM vocabulary WHERE term='shared'",
            "UPDATE vocabulary SET frequency=0 WHERE term='shared'",
            "UPDATE vocabulary SET frequency=1.5 WHERE term='shared'",
            "UPDATE vocabulary SET frequency=1 WHERE term='shared'",
        ] {
            for action in ["replace", "source", "category"] {
                let mut conn = fresh_conn();
                index_document(
                    &mut conn,
                    &idx("# One\namber shared\n# Two\ncobalt shared", "doc"),
                )
                .unwrap();
                conn.execute(mutation, []).unwrap();
                let before = index_snapshot(&conn);
                let result = match action {
                    "replace" => index_document(&mut conn, &idx("newword", "doc")).map(|_| ()),
                    "source" => purge(&mut conn, PurgeScope::Source("doc")).map(|_| ()),
                    _ => purge(&mut conn, PurgeScope::Category("test")).map(|_| ()),
                };
                assert!(result.is_err(), "{action}: {mutation}");
                assert_eq!(index_snapshot(&conn), before, "{action}: {mutation}");
            }
        }
    }

    #[test]
    fn vocabulary_cleanup_rolls_back_when_later_source_delete_fails() {
        for action in ["replace", "source", "category"] {
            let mut conn = fresh_conn();
            index_document(&mut conn, &idx("amber shared", "doc")).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER block_source_delete BEFORE DELETE ON sources
                 BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
            )
            .unwrap();
            let before = index_snapshot(&conn);
            let result = match action {
                "replace" => index_document(&mut conn, &idx("newword", "doc")).map(|_| ()),
                "source" => purge(&mut conn, PurgeScope::Source("doc")).map(|_| ()),
                _ => purge(&mut conn, PurgeScope::Category("test")).map(|_| ()),
            };
            assert!(result.is_err(), "{action}");
            assert_eq!(index_snapshot(&conn), before, "{action}");
        }
    }

    #[test]
    fn vocabulary_increment_rejects_invalid_or_overflowed_counts_atomically() {
        for value in ["0", "1.5", "9223372036854775807"] {
            let mut conn = fresh_conn();
            index_document(&mut conn, &idx("shared", "keep")).unwrap();
            conn.execute(&format!("UPDATE vocabulary SET frequency={value}"), [])
                .unwrap();
            let before = index_snapshot(&conn);
            assert!(index_document(&mut conn, &idx("shared", "new")).is_err());
            assert_eq!(index_snapshot(&conn), before);
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
    fn purge_source_reports_only_committed_removals_and_preserves_other_documents() {
        let mut conn = fresh_conn();
        let keep = index_document(&mut conn, &idx("retained amber document", "keep")).unwrap();
        let drop = index_document(&mut conn, &idx("removed cobalt document", "drop")).unwrap();

        assert_eq!(purge(&mut conn, PurgeScope::Source("absent")).unwrap(), 0);
        assert_eq!(stats(&conn).unwrap().sources_count, 2);
        for table in ["chunks", "chunks_trigram"] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 2);
            for expected in [&keep, &drop] {
                let count: i64 = conn
                    .query_row(
                        &format!("SELECT count(*) FROM {table} WHERE source_id = ?1"),
                        [expected.source_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1);
            }
        }
        let keep_hits = search(&conn, "amber", 10).unwrap();
        assert_eq!(keep_hits.len(), 1);
        assert_eq!(keep_hits[0].source_id, keep.source_id);
        assert_eq!(keep_hits[0].content, "retained amber document");
        let drop_hits = search(&conn, "cobalt", 10).unwrap();
        assert_eq!(drop_hits.len(), 1);
        assert_eq!(drop_hits[0].source_id, drop.source_id);
        assert_eq!(drop_hits[0].content, "removed cobalt document");

        assert_eq!(purge(&mut conn, PurgeScope::Source("drop")).unwrap(), 1);
        assert_eq!(purge(&mut conn, PurgeScope::Source("drop")).unwrap(), 0);
        assert_eq!(stats(&conn).unwrap().sources_count, 1);
        assert!(search(&conn, "cobalt", 10).unwrap().is_empty());
        let keep_hits = search(&conn, "amber", 10).unwrap();
        assert_eq!(keep_hits.len(), 1);
        assert_eq!(keep_hits[0].source_id, keep.source_id);
        assert_eq!(keep_hits[0].label, "keep");
        assert_eq!(keep_hits[0].content, "retained amber document");
        for table in ["chunks", "chunks_trigram"] {
            let rows: Vec<(i64, String)> = conn
                .prepare(&format!("SELECT source_id, content FROM {table}"))
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![(keep.source_id, "retained amber document".to_string())]
            );
        }
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

    // ── GOLD-ADAPT-SPEAKR-03 tests ────────────────────────────────────────

    #[test]
    fn segments_to_plain_text_formats_with_timestamp() {
        let segs = vec![
            TranscriptSegment {
                speaker: "Alice".to_string(),
                text: "Hello world".to_string(),
                start_s: Some(90.0),
            },
            TranscriptSegment {
                speaker: "Bob".to_string(),
                text: "Hi there".to_string(),
                start_s: Some(3661.0),
            },
        ];
        let out = segments_to_plain_text(&segs);
        assert!(out.contains("[00:01:30] Alice: Hello world\n"));
        assert!(out.contains("[01:01:01] Bob: Hi there\n"));
    }

    #[test]
    fn segments_to_plain_text_skips_empty_text() {
        let segs = vec![
            TranscriptSegment {
                speaker: "A".to_string(),
                text: "   ".to_string(),
                start_s: None,
            },
            TranscriptSegment {
                speaker: "B".to_string(),
                text: "real content".to_string(),
                start_s: None,
            },
        ];
        let out = segments_to_plain_text(&segs);
        assert!(!out.contains("A:"));
        assert!(out.contains("B: real content\n"));
    }

    #[test]
    fn segments_to_plain_text_no_timestamp_when_none() {
        let segs = vec![TranscriptSegment {
            speaker: "Eve".to_string(),
            text: "payload".to_string(),
            start_s: None,
        }];
        let out = segments_to_plain_text(&segs);
        assert_eq!(out, "Eve: payload\n");
        assert!(!out.contains('['));
    }

    /// Core SPEAKR-03 requirement: a string containing é (U+00E9, encoded as
    /// the two bytes 0xC3 0xA9 in UTF-8) must NEVER be truncated between
    /// those two bytes.  The format step joins the segment first, and
    /// truncation only ever lands on a char boundary.
    #[test]
    fn truncate_never_splits_multibyte_char() {
        // "ab\u{00E9}cd" = a(1) b(1) é(0xC3 0xA9 = 2 bytes) c(1) d(1) = 6 bytes total.
        // é spans byte offsets [2, 4).
        // Truncating at byte 3 (inside é) must back up to byte 2.
        let s = "ab\u{00E9}cd"; // a b é c d = 1+1+2+1+1 = 6 bytes
        assert_eq!(s.len(), 6);
        // é starts at byte offset 2, ends at byte offset 4.
        // Truncating at byte 3 (inside é) must back up to byte 2.
        let truncated = truncate_to_char_boundary(s, 3);
        assert_eq!(truncated, "ab", "must not split é at byte 3");
        // Truncating at exactly byte 4 (end of é) is fine.
        let truncated4 = truncate_to_char_boundary(s, 4);
        assert_eq!(truncated4, "ab\u{00E9}", "byte 4 is a valid boundary");
        // Full string when cap >= len.
        let full = truncate_to_char_boundary(s, 100);
        assert_eq!(full, s);
    }

    /// End-to-end: format segments containing é, then truncate; the result
    /// must be valid UTF-8 and must not contain half of a multi-byte escape.
    #[test]
    fn format_then_truncate_no_mid_unicode_cut() {
        let segs = vec![TranscriptSegment {
            speaker: "Narrator".to_string(),
            text: "café résumé naïve".to_string(),
            start_s: None,
        }];
        let plain = segments_to_plain_text(&segs);
        // plain is valid UTF-8 at this point; now truncate aggressively.
        for cap in 0..=plain.len() {
            let t = truncate_to_char_boundary(&plain, cap);
            // Must parse as valid UTF-8 — from_utf8 errors on bad boundaries.
            assert!(
                std::str::from_utf8(t.as_bytes()).is_ok(),
                "cap={cap} produced invalid UTF-8"
            );
        }
    }

    #[test]
    fn hard_slice_does_not_split_multibyte() {
        // Build a string where every other char is é (2-byte).
        let s: String = "x\u{00E9}".repeat(200); // 400 bytes
        let slices = hard_slice(&s, 3); // cap=3; each é must not be split
        for slice in &slices {
            assert!(
                std::str::from_utf8(slice.as_bytes()).is_ok(),
                "hard_slice produced invalid UTF-8: {slice:?}"
            );
        }
    }
}
