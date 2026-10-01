//! Explicit, local-only code-chunk vector corpora.
//!
//! Repository chunks are produced only by `code-map reindex-embeddings`; normal
//! coding recall may embed its current prompt to query a complete corpus, but
//! never writes or backfills chunk vectors.

use std::cmp::Ordering;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::recall::{RelevantFile, RootGenerationSnapshot};

pub(crate) const REINDEX_BATCH_CAP: usize = 64;
pub(crate) const QUERY_CANDIDATE_CAP: usize = 128;
/// Refuse corrupt metadata before it can turn into a pathological BLOB
/// allocation.  Local providers have much smaller dimensions today; this is a
/// defensive persistence ceiling, not a product configuration limit.
const MAX_VECTOR_DIMENSION: usize = 16_384;
const MAX_VECTOR_BLOB_BYTES: usize = MAX_VECTOR_DIMENSION * std::mem::size_of::<f32>();

fn vector_bytes(dimension: usize) -> Option<usize> {
    (dimension > 0 && dimension <= MAX_VECTOR_DIMENSION)
        .then(|| dimension.checked_mul(std::mem::size_of::<f32>()))
        .flatten()
        .filter(|bytes| *bytes <= MAX_VECTOR_BLOB_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodeChunkRef {
    pub corpus_id: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub path: String,
    pub source_sha256: String,
    pub ordinal: u32,
}

impl CodeChunkRef {
    pub(crate) fn encode(&self) -> String {
        format!(
            "v1|{}|{}|{}|{}|{}|{}",
            self.corpus_id, self.root_identity, self.index_generation, self.path,
            self.source_sha256, self.ordinal
        )
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        let mut fields = value.split('|');
        let version = fields.next()?;
        let corpus_id = fields.next()?.to_owned();
        let root_identity = fields.next()?.to_owned();
        let index_generation = fields.next()?.parse().ok()?;
        let path = fields.next()?.to_owned();
        let source_sha256 = fields.next()?.to_owned();
        let ordinal = fields.next()?.parse().ok()?;
        if version != "v1"
            || fields.next().is_some()
            || corpus_id.is_empty()
            || root_identity.is_empty()
            || index_generation <= 0
            || !valid_relative_path(&path)
            || !valid_sha256(&source_sha256)
        {
            return None;
        }
        Some(Self { corpus_id, root_identity, index_generation, path, source_sha256, ordinal })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodeVectorCorpus {
    pub(crate) id: String,
    pub(crate) root: String,
    pub(crate) root_identity: String,
    pub(crate) index_generation: i64,
    pub(crate) chunk_generation: i64,
    pub(crate) provider_generation: String,
    pub(crate) model: String,
    pub(crate) dimension: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SemanticChunk {
    pub(crate) path: String,
    pub(crate) source_sha256: String,
    pub(crate) ordinal: u32,
    pub(crate) similarity: f32,
}

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS code_map_vector_corpora (
           corpus_id TEXT PRIMARY KEY NOT NULL,
           root TEXT NOT NULL,
           root_identity TEXT NOT NULL,
           index_generation INTEGER NOT NULL,
           chunk_generation INTEGER NOT NULL,
           provider_generation TEXT NOT NULL,
           model TEXT NOT NULL,
           dimension INTEGER NOT NULL,
           state TEXT NOT NULL CHECK(state IN ('staging','complete')),
           UNIQUE(root_identity,index_generation,chunk_generation,provider_generation)
         );
         CREATE TABLE IF NOT EXISTS code_map_chunk_vectors (
           corpus_id TEXT NOT NULL REFERENCES code_map_vector_corpora(corpus_id) ON DELETE CASCADE,
           source_ref TEXT NOT NULL UNIQUE,
           path TEXT NOT NULL,
           source_sha256 TEXT NOT NULL,
           ordinal INTEGER NOT NULL,
           embedding BLOB NOT NULL,
           PRIMARY KEY(corpus_id,path,source_sha256,ordinal)
         );
         CREATE INDEX IF NOT EXISTS idx_code_map_chunk_vectors_corpus
           ON code_map_chunk_vectors(corpus_id,path,source_sha256,ordinal);"
    ).context("ensure code-vector schema")
}

pub(crate) fn complete_corpus_for_snapshot(
    conn: &Connection,
    snapshot: &RootGenerationSnapshot,
    provider: &crate::providers::LocalEmbeddingProvider,
) -> Result<Option<CodeVectorCorpus>> {
    let generation = provider.generation();
    if snapshot.index_generation <= 0 || snapshot.index_generation != snapshot.chunk_generation {
        return Ok(None);
    }
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root=?1 AND root_identity=?2 AND index_generation=?3 AND chunk_generation=?3)",
        params![snapshot.root.display(), snapshot.root.identity().as_str(), snapshot.index_generation],
        |row| row.get(0),
    ).context("verify active root generation for code-vector corpus")?;
    if !active { return Ok(None); }
    conn.query_row(
        "SELECT corpus_id,root,root_identity,index_generation,chunk_generation,provider_generation,model,dimension
         FROM code_map_vector_corpora
         WHERE root_identity=?1 AND index_generation=?2 AND chunk_generation=?2
           AND provider_generation=?3 AND model=?4 AND dimension=?5 AND state='complete'",
        params![snapshot.root.identity().as_str(), snapshot.index_generation, generation.id(), generation.expected_model(), generation.dimension() as i64],
        |row| Ok(CodeVectorCorpus {
            id: row.get(0)?, root: row.get(1)?, root_identity: row.get(2)?,
            index_generation: row.get(3)?, chunk_generation: row.get(4)?,
            provider_generation: row.get(5)?, model: row.get(6)?,
            dimension: usize::try_from(row.get::<_, i64>(7)?)
                .ok()
                .filter(|dimension| vector_bytes(*dimension).is_some())
                .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(7, 0))?,
        }),
    ).optional().context("find complete code-vector corpus")
}

/// Cheap read-only gate used before provider construction.  Provider-specific
/// eligibility is checked again after the sealed provider is available.
pub(crate) fn has_complete_corpus_for_snapshot(
    conn: &Connection,
    snapshot: &RootGenerationSnapshot,
) -> Result<bool> {
    if snapshot.index_generation <= 0 || snapshot.index_generation != snapshot.chunk_generation { return Ok(false); }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM code_map_vector_corpora WHERE root_identity=?1 AND index_generation=?2 AND chunk_generation=?2 AND state='complete')",
        params![snapshot.root.identity().as_str(), snapshot.index_generation],
        |row| row.get(0),
    ).context("probe complete code-vector corpus")
}

pub(crate) fn query_pre_ranked_files(
    conn: &Connection,
    snapshot: &RootGenerationSnapshot,
    provider: &crate::providers::LocalEmbeddingProvider,
    query: &[f32],
    ranked_files: &[RelevantFile],
) -> Result<Vec<SemanticChunk>> {
    let Some(corpus) = complete_corpus_for_snapshot(conn, snapshot, provider)? else { return Ok(Vec::new()); };
    if query.len() != corpus.dimension || query.iter().any(|value| !value.is_finite()) {
        return Ok(Vec::new());
    }
    let expected_bytes = match vector_bytes(corpus.dimension) { Some(bytes) => bytes, None => return Ok(Vec::new()) };
    let mut statement = conn.prepare(
        "SELECT source_ref,path,source_sha256,ordinal,length(embedding),embedding FROM code_map_chunk_vectors
         WHERE corpus_id=?1 AND path=?2 ORDER BY ordinal ASC LIMIT ?3"
    )?;
    let mut result = Vec::new();
    let mut scanned = 0usize;
    for file in ranked_files {
        let remaining = QUERY_CANDIDATE_CAP.saturating_sub(scanned);
        if remaining == 0 { break; }
        let mut rows = statement.query(params![corpus.id, file.path, remaining as i64 + 1])?;
        let mut fetched = 0usize;
        while let Some(row) = rows.next()? {
            fetched += 1;
            if fetched > remaining { break; }
            scanned += 1;
            let source_ref: String = row.get(0)?;
            let path: String = row.get(1)?;
            let sha: String = row.get(2)?;
            let ordinal: i64 = row.get(3)?;
            let measured: i64 = row.get(4)?;
            let Ok(measured) = usize::try_from(measured) else { continue; };
            if measured != expected_bytes { continue; }
            let Ok(ordinal) = u32::try_from(ordinal) else { continue; };
            let blob: Vec<u8> = row.get(5)?;
            let Some(reference) = CodeChunkRef::parse(&source_ref) else { continue; };
            if reference.corpus_id != corpus.id || reference.root_identity != corpus.root_identity
                || reference.index_generation != corpus.index_generation || reference.path != path
                || reference.source_sha256 != sha || reference.ordinal != ordinal { continue; }
            let Some(vector) = decode_vector(&blob, corpus.dimension) else { continue; };
            if !current_chunk_exists(conn, &corpus, &reference)? { continue; }
            result.push(SemanticChunk { path, source_sha256: sha, ordinal, similarity: cosine(query, &vector) });
        }
        if fetched > remaining { break; }
    }
    result.sort_by(|left, right| right.similarity.partial_cmp(&left.similarity).unwrap_or(Ordering::Equal)
        .then_with(|| left.path.cmp(&right.path)).then_with(|| left.ordinal.cmp(&right.ordinal)));
    Ok(result)
}

fn current_chunk_exists(conn: &Connection, corpus: &CodeVectorCorpus, reference: &CodeChunkRef) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM code_map_roots r JOIN code_map_chunks c ON c.root=r.root
          WHERE r.root=?1 AND r.root_identity=?2 AND r.index_generation=?3 AND r.chunk_generation=?3
            AND c.path=?4 AND c.source_sha256=?5 AND c.ordinal=?6)",
        params![corpus.root, corpus.root_identity, corpus.index_generation, reference.path, reference.source_sha256, reference.ordinal],
        |row| row.get(0),
    ).context("resolve current code-vector source reference")
}

fn valid_relative_path(path: &str) -> bool { !path.is_empty() && !path.starts_with('/') && !path.contains("..") && !path.contains('|') }
fn valid_sha256(value: &str) -> bool { value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) }
fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let dot: f32 = left.iter().zip(right).map(|(a, b)| a * b).sum();
    let left_norm: f32 = left.iter().map(|value| value * value).sum();
    let right_norm: f32 = right.iter().map(|value| value * value).sum();
    let denominator = left_norm.sqrt() * right_norm.sqrt();
    let score = dot / denominator;
    if denominator.is_finite() && denominator > 0.0 && score.is_finite() { score } else { -1.0 }
}
fn decode_vector(blob: &[u8], dimension: usize) -> Option<Vec<f32>> {
    if blob.len() != vector_bytes(dimension)? { return None; }
    let vector = blob.chunks_exact(4).map(|bytes| f32::from_le_bytes(bytes.try_into().ok()?)).collect::<Option<Vec<_>>>()?;
    vector.iter().all(|value| value.is_finite()).then_some(vector)
}

/// Explicit producer. Every source row is copied out before the first await;
/// every completed embed is admitted by a fresh immediate transaction.
pub(crate) async fn reindex_current(
    db_path: &std::path::Path,
    snapshot: &RootGenerationSnapshot,
    provider: &crate::providers::LocalEmbeddingProvider,
    full: bool,
) -> Result<usize> {
    let mut conn = crate::code_map::persist::open(db_path)?;
    ensure_schema(&conn)?;
    let generation = provider.generation().clone();
    let Some(corpus) = create_staging_corpus(&mut conn, snapshot, &generation)? else { return Ok(0); };
    if full {
        clear_staging_vectors(&mut conn, &corpus)?;
    } else {
        copy_unchanged_from_predecessor(&mut conn, &corpus)?;
    }
    drop(conn);
    let mut stored = 0usize;
    loop {
        // This bounded source read ends before every provider await.
        let pending = {
            let conn = crate::code_map::persist::open(db_path)?;
            load_pending_chunks(&conn, &corpus, REINDEX_BATCH_CAP)?
        };
        if pending.is_empty() { break; }
        let pending_len = pending.len();
        let mut failed = false;
        for chunk in pending {
            let vector = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                crate::memory::embeddings::embed_one(&chunk.text, provider),
            ).await.ok().flatten();
            let Some(vector) = vector else { failed = true; continue; };
            let mut conn = crate::code_map::persist::open(db_path)?;
            if store_if_current(&mut conn, snapshot, provider, &corpus, &chunk, &vector)? { stored += 1; } else { failed = true; }
        }
        // A failed embedding must leave staging for an explicit retry, rather
        // than looping forever or silently publishing an incomplete corpus.
        if failed {
            anyhow::bail!("local embedding reindex stopped with an incomplete staging corpus; retry the explicit command");
        }
        if pending_len < REINDEX_BATCH_CAP { break; }
    }
    let mut conn = crate::code_map::persist::open(db_path)?;
    complete_if_exhaustive(&mut conn, snapshot, provider, &corpus)?;
    Ok(stored)
}

fn clear_staging_vectors(conn: &mut Connection, corpus: &CodeVectorCorpus) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("UPDATE code_map_vector_corpora SET state='staging' WHERE corpus_id=?1", [&corpus.id])?;
    tx.execute("DELETE FROM code_map_chunk_vectors WHERE corpus_id=?1", [&corpus.id])?;
    tx.commit()?;
    Ok(())
}

#[derive(Clone)]
struct PendingChunk { path: String, source_sha256: String, ordinal: u32, text: String }

fn create_staging_corpus(conn: &mut Connection, snapshot: &RootGenerationSnapshot, generation: &crate::providers::EmbeddingGeneration) -> Result<Option<CodeVectorCorpus>> {
    if snapshot.index_generation <= 0 || snapshot.index_generation != snapshot.chunk_generation { return Ok(None); }
    anyhow::ensure!(
        vector_bytes(generation.dimension()).is_some(),
        "sealed local embedding dimension exceeds code-vector persistence bound"
    );
    let corpus = CodeVectorCorpus {
        id: format!("cv1:{}:{}:{}", snapshot.root.identity().as_str(), snapshot.index_generation, generation.id()),
        root: snapshot.root.display().to_owned(), root_identity: snapshot.root.identity().as_str().to_owned(),
        index_generation: snapshot.index_generation, chunk_generation: snapshot.chunk_generation,
        provider_generation: generation.id().to_owned(), model: generation.expected_model().to_owned(), dimension: generation.dimension(),
    };
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("INSERT OR IGNORE INTO code_map_vector_corpora (corpus_id,root,root_identity,index_generation,chunk_generation,provider_generation,model,dimension,state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'staging')",
        params![corpus.id, corpus.root, corpus.root_identity, corpus.index_generation, corpus.chunk_generation, corpus.provider_generation, corpus.model, i64::try_from(corpus.dimension)?])?;
    tx.commit()?;
    Ok(Some(corpus))
}

fn load_pending_chunks(conn: &Connection, corpus: &CodeVectorCorpus, cap: usize) -> Result<Vec<PendingChunk>> {
    let mut stmt = conn.prepare("SELECT c.path,c.source_sha256,c.ordinal,c.text FROM code_map_chunks c JOIN code_map_roots r ON r.root=c.root WHERE r.root=?1 AND r.root_identity=?2 AND r.index_generation=?3 AND r.chunk_generation=?3 AND NOT EXISTS (SELECT 1 FROM code_map_chunk_vectors v WHERE v.corpus_id=?4 AND v.path=c.path AND v.source_sha256=c.source_sha256 AND v.ordinal=c.ordinal) ORDER BY c.path,c.ordinal LIMIT ?5")?;
    stmt.query_map(params![corpus.root, corpus.root_identity, corpus.index_generation, corpus.id, cap as i64], |row| Ok(PendingChunk { path: row.get(0)?, source_sha256: row.get(1)?, ordinal: row.get::<_, i64>(2)? as u32, text: row.get(3)? }))?
        .collect::<rusqlite::Result<Vec<_>>>().context("load bounded pending code chunks")
}

/// Delta mode copies only byte-identical current chunks from the last complete
/// local corpus with the same sealed provider generation.  Its source refs are
/// rebuilt for the new corpus, so a copied vector cannot be queried as part of
/// its predecessor.  Full mode simply skips this function.
fn copy_unchanged_from_predecessor(conn: &mut Connection, corpus: &CodeVectorCorpus) -> Result<()> {
    let previous = conn.query_row(
        "SELECT corpus_id FROM code_map_vector_corpora WHERE root_identity=?1 AND provider_generation=?2 AND model=?3 AND dimension=?4 AND state='complete' AND corpus_id<>?5 ORDER BY rowid DESC LIMIT 1",
        params![corpus.root_identity, corpus.provider_generation, corpus.model, corpus.dimension as i64, corpus.id],
        |row| row.get::<_, String>(0),
    ).optional()?;
    let Some(previous) = previous else { return Ok(()); };
    let expected_bytes = vector_bytes(corpus.dimension).context("invalid sealed code-vector dimension")?;
    let mut after_path = String::new();
    let mut after_ordinal = -1_i64;
    loop {
        let mut stmt = conn.prepare(
            "SELECT v.path,v.source_sha256,v.ordinal,length(v.embedding),v.embedding
             FROM code_map_chunk_vectors v
             JOIN code_map_chunks c ON c.root=?1 AND c.path=v.path AND c.source_sha256=v.source_sha256 AND c.ordinal=v.ordinal
             JOIN code_map_roots r ON r.root=c.root
             WHERE v.corpus_id=?2 AND r.root_identity=?3 AND r.index_generation=?4 AND r.chunk_generation=?4
               AND length(v.embedding)=?5
               AND (v.path > ?6 OR (v.path = ?6 AND v.ordinal > ?7))
             ORDER BY v.path,v.ordinal LIMIT ?8",
        )?;
        let mut rows = stmt.query(params![corpus.root, previous, corpus.root_identity, corpus.index_generation, i64::try_from(expected_bytes)?, &after_path, after_ordinal, REINDEX_BATCH_CAP as i64])?;
        let mut candidates = Vec::new();
        let mut fetched = 0usize;
        while let Some(row) = rows.next()? {
            fetched += 1;
            let path: String = row.get(0)?;
            let source_sha256: String = row.get(1)?;
            let raw_ordinal: i64 = row.get(2)?;
            let measured: i64 = row.get(3)?;
            after_path = path.clone();
            after_ordinal = raw_ordinal;
            let Ok(ordinal) = u32::try_from(raw_ordinal) else { continue; };
            if usize::try_from(measured).ok() != Some(expected_bytes) { continue; }
            let embedding: Vec<u8> = row.get(4)?;
            if decode_vector(&embedding, corpus.dimension).is_none() { continue; }
            candidates.push((path, source_sha256, ordinal, embedding));
        }
        drop(rows);
        drop(stmt);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (path, source_sha256, ordinal, embedding) in candidates {
            let reference = CodeChunkRef { corpus_id: corpus.id.clone(), root_identity: corpus.root_identity.clone(), index_generation: corpus.index_generation, path: path.clone(), source_sha256: source_sha256.clone(), ordinal };
            tx.execute(
                "INSERT OR IGNORE INTO code_map_chunk_vectors (corpus_id,source_ref,path,source_sha256,ordinal,embedding) VALUES (?1,?2,?3,?4,?5,?6)",
                params![corpus.id, reference.encode(), path, source_sha256, ordinal, embedding],
            )?;
        }
        tx.commit()?;
        if fetched < REINDEX_BATCH_CAP { break; }
    }
    Ok(())
}

fn store_if_current(conn: &mut Connection, snapshot: &RootGenerationSnapshot, provider: &crate::providers::LocalEmbeddingProvider, corpus: &CodeVectorCorpus, chunk: &PendingChunk, vector: &[f32]) -> Result<bool> {
    if vector_bytes(corpus.dimension).is_none() || vector.len() != corpus.dimension || vector.iter().any(|value| !value.is_finite()) { return Ok(false); }
    let generation = provider.generation();
    if corpus.root != snapshot.root.display()
        || corpus.root_identity != snapshot.root.identity().as_str()
        || corpus.index_generation != snapshot.index_generation
        || corpus.chunk_generation != snapshot.chunk_generation
        || corpus.provider_generation != generation.id()
        || corpus.model != generation.expected_model()
        || corpus.dimension != generation.dimension() { return Ok(false); }
    Ok(provider.with_current_config(|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM code_map_roots r JOIN code_map_chunks c ON c.root=r.root WHERE r.root=?1 AND r.root_identity=?2 AND r.index_generation=?3 AND r.chunk_generation=?3 AND c.path=?4 AND c.source_sha256=?5 AND c.ordinal=?6)", params![snapshot.root.display(), snapshot.root.identity().as_str(), snapshot.index_generation, chunk.path, chunk.source_sha256, chunk.ordinal], |row| row.get(0))?;
        if !current { tx.rollback()?; return Ok(false); }
        let reference = CodeChunkRef { corpus_id: corpus.id.clone(), root_identity: corpus.root_identity.clone(), index_generation: corpus.index_generation, path: chunk.path.clone(), source_sha256: chunk.source_sha256.clone(), ordinal: chunk.ordinal };
        tx.execute("INSERT OR REPLACE INTO code_map_chunk_vectors (corpus_id,source_ref,path,source_sha256,ordinal,embedding) VALUES (?1,?2,?3,?4,?5,?6)", params![corpus.id, reference.encode(), chunk.path, chunk.source_sha256, chunk.ordinal, encode_vector(vector)])?;
        tx.commit()?;
        Ok(true)
    })?.unwrap_or(false))
}

fn complete_if_exhaustive(conn: &mut Connection, snapshot: &RootGenerationSnapshot, provider: &crate::providers::LocalEmbeddingProvider, corpus: &CodeVectorCorpus) -> Result<()> {
    let generation = provider.generation();
    if corpus.root != snapshot.root.display()
        || corpus.root_identity != snapshot.root.identity().as_str()
        || corpus.index_generation != snapshot.index_generation
        || corpus.chunk_generation != snapshot.chunk_generation
        || corpus.provider_generation != generation.id()
        || corpus.model != generation.expected_model()
        || corpus.dimension != generation.dimension() { return Ok(()); }
    let _ = provider.with_current_config(|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root=?1 AND root_identity=?2 AND index_generation=?3 AND chunk_generation=?3)", params![snapshot.root.display(), snapshot.root.identity().as_str(), snapshot.index_generation], |row| row.get(0))?;
        if !active { tx.rollback()?; return Ok(()); }
        let expected: i64 = tx.query_row("SELECT COUNT(*) FROM code_map_chunks c JOIN code_map_roots r ON r.root=c.root WHERE r.root=?1 AND r.root_identity=?2 AND r.index_generation=?3 AND r.chunk_generation=?3", params![snapshot.root.display(), snapshot.root.identity().as_str(), snapshot.index_generation], |row| row.get(0))?;
        let actual: i64 = tx.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors WHERE corpus_id=?1", [&corpus.id], |row| row.get(0))?;
        if expected == actual {
            tx.execute("UPDATE code_map_vector_corpora SET state='complete' WHERE corpus_id=?1", [&corpus.id])?;
        // The complete generation is the sole query authority.  Discarding
        // predecessors only after this update keeps interruption recoverable.
        tx.execute(
            "DELETE FROM code_map_vector_corpora WHERE root_identity=?1 AND provider_generation=?2 AND corpus_id<>?3",
            params![corpus.root_identity, corpus.provider_generation, corpus.id],
        )?;
        }
        tx.commit()?;
        Ok(())
    })?;
    Ok(())
}

fn encode_vector(vector: &[f32]) -> Vec<u8> { vector.iter().flat_map(|value| value.to_le_bytes()).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedEmbed;

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for FixedEmbed {
        fn name(&self) -> &'static str { "vector-test" }
        fn default_dim(&self) -> usize { 2 }
        async fn embed(
            &self,
            _request: crate::providers::embed::EmbedRequest,
        ) -> Result<crate::providers::embed::EmbedResponse> {
            Ok(crate::providers::embed::EmbedResponse {
                vector: vec![1.0, 0.0], model: "vector-test".into(),
                latency: std::time::Duration::ZERO,
            })
        }
    }

    fn vector_fixture() -> (tempfile::TempDir, Connection, RootGenerationSnapshot, crate::providers::LocalEmbeddingProvider, CodeVectorCorpus, PendingChunk) {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(dir.path()).unwrap();
        let snapshot = RootGenerationSnapshot { root: root.clone(), index_generation: 1, graph_generation: 1, chunk_generation: 1 };
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch("CREATE TABLE code_map_roots (root TEXT PRIMARY KEY, root_identity TEXT, index_generation INTEGER, chunk_generation INTEGER); CREATE TABLE code_map_chunks (root TEXT, path TEXT, source_sha256 TEXT, ordinal INTEGER, text TEXT);").unwrap();
        conn.execute("INSERT INTO code_map_roots VALUES (?1,?2,1,1)", params![root.display(), root.identity().as_str()]).unwrap();
        let sha = "a".repeat(64);
        conn.execute("INSERT INTO code_map_chunks VALUES (?1,'src/lib.rs',?2,0,'fn selected() {}')", params![root.display(), &sha]).unwrap();
        let provider = crate::providers::LocalEmbeddingProvider::for_test(std::sync::Arc::new(FixedEmbed));
        let corpus = CodeVectorCorpus { id: "current".into(), root: root.display().to_owned(), root_identity: root.identity().as_str().to_owned(), index_generation: 1, chunk_generation: 1, provider_generation: provider.generation().id().to_owned(), model: provider.generation().expected_model().to_owned(), dimension: provider.generation().dimension() };
        conn.execute("INSERT INTO code_map_vector_corpora VALUES (?1,?2,?3,1,1,?4,?5,2,'staging')", params![&corpus.id, &corpus.root, &corpus.root_identity, &corpus.provider_generation, &corpus.model]).unwrap();
        let chunk = PendingChunk { path: "src/lib.rs".into(), source_sha256: sha, ordinal: 0, text: "fn selected() {}".into() };
        (dir, conn, snapshot, provider, corpus, chunk)
    }
    #[test]
    fn canonical_code_chunk_reference_round_trips_and_rejects_escape() {
        let reference = CodeChunkRef { corpus_id: "c".into(), root_identity: "r".into(), index_generation: 1, path: "src/lib.rs".into(), source_sha256: "a".repeat(64), ordinal: 2 };
        assert_eq!(CodeChunkRef::parse(&reference.encode()), Some(reference));
        assert!(CodeChunkRef::parse("v1|c|r|1|../x|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|2").is_none());
    }

    #[test]
    fn cosine_scoring_is_exact_and_rejects_a_zero_vector() {
        assert!((cosine(&[1.0, 0.0], &[2.0, 0.0]) - 1.0).abs() < f32::EPSILON);
        assert!((cosine(&[1.0, 0.0], &[0.0, 2.0])).abs() < f32::EPSILON);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 0.0]), -1.0);
    }

    #[test]
    fn bounded_vector_decode_rejects_invalid_dimension_and_blob_before_materialization() {
        assert!(vector_bytes(0).is_none());
        assert!(vector_bytes(MAX_VECTOR_DIMENSION + 1).is_none());
        assert!(decode_vector(&[0; 3], 1).is_none());
        assert!(decode_vector(&vec![0; MAX_VECTOR_BLOB_BYTES + 4], MAX_VECTOR_DIMENSION).is_none());
    }

    #[test]
    fn staging_corpus_is_invisible_until_complete_and_completion_can_retire_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(dir.path()).unwrap();
        let snapshot = RootGenerationSnapshot { root: root.clone(), index_generation: 3, graph_generation: 3, chunk_generation: 3 };
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute("INSERT INTO code_map_vector_corpora VALUES ('old',?1,?2,2,2,'g','m',2,'complete')", params![root.display(), root.identity().as_str()]).unwrap();
        conn.execute("INSERT INTO code_map_vector_corpora VALUES ('new',?1,?2,3,3,'g','m',2,'staging')", params![root.display(), root.identity().as_str()]).unwrap();
        assert!(!has_complete_corpus_for_snapshot(&conn, &snapshot).unwrap());
        conn.execute("UPDATE code_map_vector_corpora SET state='complete' WHERE corpus_id='new'", []).unwrap();
        assert!(has_complete_corpus_for_snapshot(&conn, &snapshot).unwrap());
        conn.execute("DELETE FROM code_map_vector_corpora WHERE corpus_id='old'", []).unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM code_map_vector_corpora", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn delta_reuses_more_than_one_batch_only_for_exact_current_chunk_identity() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch(
            "CREATE TABLE code_map_roots (root TEXT PRIMARY KEY, root_identity TEXT, index_generation INTEGER, chunk_generation INTEGER);
             CREATE TABLE code_map_chunks (root TEXT, path TEXT, source_sha256 TEXT, ordinal INTEGER);",
        ).unwrap();
        conn.execute("INSERT INTO code_map_roots VALUES ('/r','id',2,2)", []).unwrap();
        conn.execute("INSERT INTO code_map_vector_corpora VALUES ('old','/r','id',1,1,'g','m',2,'complete')", []).unwrap();
        conn.execute("INSERT INTO code_map_vector_corpora VALUES ('new','/r','id',2,2,'g','m',2,'staging')", []).unwrap();
        let embedding = encode_vector(&[1.0, 0.0]);
        for ordinal in 0..(REINDEX_BATCH_CAP + 1) {
            let path = format!("src/{ordinal:03}.rs");
            let sha = format!("{:064x}", ordinal + 1);
            conn.execute("INSERT INTO code_map_chunks VALUES ('/r',?1,?2,?3)", params![path, sha, ordinal as i64]).unwrap();
            conn.execute(
                "INSERT INTO code_map_chunk_vectors VALUES ('old',?1,?2,?3,?4,?5)",
                params![format!("old-{ordinal}"), path, sha, ordinal as i64, &embedding],
            ).unwrap();
        }
        // A changed identity and a deleted predecessor row cannot be carried
        // into the successor even though the path/root remain plausible.
        conn.execute("INSERT INTO code_map_chunks VALUES ('/r','src/changed.rs',?1,0)", ["b".repeat(64)]).unwrap();
        conn.execute(
            "INSERT INTO code_map_chunk_vectors VALUES ('old','old-changed','src/changed.rs',?1,0,?2)",
            params!["a".repeat(64), &embedding],
        ).unwrap();
        conn.execute(
            "INSERT INTO code_map_chunk_vectors VALUES ('old','old-deleted','src/deleted.rs',?1,0,?2)",
            params!["c".repeat(64), &embedding],
        ).unwrap();
        let corpus = CodeVectorCorpus { id: "new".into(), root: "/r".into(), root_identity: "id".into(), index_generation: 2, chunk_generation: 2, provider_generation: "g".into(), model: "m".into(), dimension: 2 };
        copy_unchanged_from_predecessor(&mut conn, &corpus).unwrap();
        let copied: i64 = conn.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors WHERE corpus_id='new'", [], |row| row.get(0)).unwrap();
        assert_eq!(copied as usize, REINDEX_BATCH_CAP + 1);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors WHERE corpus_id='new' AND path IN ('src/changed.rs','src/deleted.rs')", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn store_refuses_source_or_provider_generation_drift_before_vector_write() {
        let (_dir, mut conn, snapshot, provider, corpus, chunk) = vector_fixture();
        conn.execute("UPDATE code_map_roots SET index_generation=2, chunk_generation=2", []).unwrap();
        assert!(!store_if_current(&mut conn, &snapshot, &provider, &corpus, &chunk, &[1.0, 0.0]).unwrap());
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        conn.execute("UPDATE code_map_roots SET index_generation=1, chunk_generation=1", []).unwrap();
        let mut provider_drift = corpus.clone();
        provider_drift.provider_generation = "other-sealed-generation".into();
        assert!(!store_if_current(&mut conn, &snapshot, &provider, &provider_drift, &chunk, &[1.0, 0.0]).unwrap());
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn staging_vectors_remain_unpublished_and_nonqueryable() {
        let (_dir, conn, snapshot, provider, corpus, chunk) = vector_fixture();
        let reference = CodeChunkRef { corpus_id: corpus.id.clone(), root_identity: corpus.root_identity.clone(), index_generation: 1, path: chunk.path.clone(), source_sha256: chunk.source_sha256.clone(), ordinal: chunk.ordinal };
        conn.execute("INSERT INTO code_map_chunk_vectors VALUES (?1,?2,?3,?4,?5,?6)", params![&corpus.id, reference.encode(), &chunk.path, &chunk.source_sha256, 0_i64, encode_vector(&[1.0, 0.0])]).unwrap();
        let files = vec![RelevantFile { root: corpus.root.clone(), path: chunk.path.clone(), identifier_hits: 1, matched_symbols: vec!["selected".into()], path_keyword_overlap: 0 }];
        assert!(!has_complete_corpus_for_snapshot(&conn, &snapshot).unwrap());
        assert!(query_pre_ranked_files(&conn, &snapshot, &provider, &[1.0, 0.0], &files).unwrap().is_empty());
    }

    #[test]
    fn query_rejects_complete_corpus_after_root_generation_advances() {
        let (_dir, conn, snapshot, provider, corpus, chunk) = vector_fixture();
        let reference = CodeChunkRef { corpus_id: corpus.id.clone(), root_identity: corpus.root_identity.clone(), index_generation: 1, path: chunk.path.clone(), source_sha256: chunk.source_sha256.clone(), ordinal: chunk.ordinal };
        conn.execute("INSERT INTO code_map_chunk_vectors VALUES (?1,?2,?3,?4,?5,?6)", params![&corpus.id, reference.encode(), &chunk.path, &chunk.source_sha256, 0_i64, encode_vector(&[1.0, 0.0])]).unwrap();
        conn.execute("UPDATE code_map_vector_corpora SET state='complete' WHERE corpus_id=?1", [&corpus.id]).unwrap();
        conn.execute("UPDATE code_map_roots SET index_generation=2, chunk_generation=2", []).unwrap();
        let stale_snapshot = RootGenerationSnapshot { root: snapshot.root.clone(), index_generation: 2, graph_generation: 2, chunk_generation: 2 };
        let files = vec![RelevantFile { root: corpus.root.clone(), path: chunk.path.clone(), identifier_hits: 1, matched_symbols: vec!["selected".into()], path_keyword_overlap: 0 }];
        assert!(query_pre_ranked_files(&conn, &stale_snapshot, &provider, &[1.0, 0.0], &files).unwrap().is_empty());
    }

    #[test]
    fn changed_actual_config_keeps_store_and_finalize_staging() {
        let (dir, mut conn, snapshot, _provider, corpus, chunk) = vector_fixture();
        let config_path = dir.path().join("freedom.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap()).unwrap();
        let provider = crate::providers::LocalEmbeddingProvider::for_test_with_config(std::sync::Arc::new(FixedEmbed), &config_path).unwrap();
        let corpus = CodeVectorCorpus { provider_generation: provider.generation().id().to_owned(), model: provider.generation().expected_model().to_owned(), dimension: provider.generation().dimension(), ..corpus };
        conn.execute("UPDATE code_map_vector_corpora SET provider_generation=?2, model=?3, dimension=?4 WHERE corpus_id=?1", params![&corpus.id, &corpus.provider_generation, &corpus.model, corpus.dimension as i64]).unwrap();
        crate::config::FreedomConfig::update_at(&config_path, |config| {
            config.embed.model = crate::config::embedding::EmbeddingModel::BgeM3;
            Ok(())
        }).unwrap();
        assert!(!store_if_current(&mut conn, &snapshot, &provider, &corpus, &chunk, &[1.0, 0.0]).unwrap());
        complete_if_exhaustive(&mut conn, &snapshot, &provider, &corpus).unwrap();
        assert_eq!(conn.query_row("SELECT state FROM code_map_vector_corpora WHERE corpus_id=?1", [&corpus.id], |row| row.get::<_, String>(0)).unwrap(), "staging");
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM code_map_chunk_vectors", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn stale_empty_staging_corpus_cannot_complete_or_be_admitted() {
        let (_dir, mut conn, snapshot, provider, corpus, _chunk) = vector_fixture();
        conn.execute("UPDATE code_map_roots SET index_generation=2, chunk_generation=2", []).unwrap();
        complete_if_exhaustive(&mut conn, &snapshot, &provider, &corpus).unwrap();
        assert_eq!(conn.query_row("SELECT state FROM code_map_vector_corpora WHERE corpus_id=?1", [&corpus.id], |row| row.get::<_, String>(0)).unwrap(), "staging");
        assert!(complete_corpus_for_snapshot(&conn, &snapshot, &provider).unwrap().is_none());
    }

    #[tokio::test]
    async fn reindex_current_publishes_exhaustive_corpus_with_deterministic_local_provider() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("lib.rs"), "pub fn selected() {}\n").unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
        let db = dir.path().join("code-map.db");
        crate::code_map::rebuild_snapshot(&root, &db, Default::default()).unwrap();
        let conn = crate::code_map::persist::open(&db).unwrap();
        let snapshot = crate::code_map::recall::resolve_active_root_snapshot(&conn, &repo).unwrap().unwrap();
        drop(conn);
        let provider = crate::providers::LocalEmbeddingProvider::for_test(std::sync::Arc::new(FixedEmbed));
        assert!(reindex_current(&db, &snapshot, &provider, true).await.unwrap() > 0);
        let conn = crate::code_map::persist::open(&db).unwrap();
        assert!(complete_corpus_for_snapshot(&conn, &snapshot, &provider).unwrap().is_some());
    }
}
