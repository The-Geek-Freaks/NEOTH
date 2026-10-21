# Memory Codemap — Embedding Store

**Last Updated:** 2026-09-13
**Entry Points:** `SRC/neothd/src/memory/embeddings.rs`, `SRC/neothd/src/memory/store.rs`, `SRC/neothd/src/memory/session_start_recall.rs`

## Architecture

```
idx_embedding (SQLite table, schema v6)
  |
  | upsert(conn, source_kind, source_ref, model, embedding[])
  |   ON CONFLICT(source_kind, source_ref) DO UPDATE
  |   → rowid
  |
  | find_similar(conn, query[], kind_filter?, top_k)
  |   scan WHERE dim = ? [AND source_kind = ?]
  |   → dot(query, candidate) per row
  |   → sort by similarity DESC, created_at DESC
  |   → truncate to top_k
  |   → Vec<SimilarHit>
  |
  | delete(conn, source_kind, source_ref) → usize
  | count(conn) → i64
```

## Key Modules

| Module | Purpose | Key Exports |
|--------|---------|-------------|
| `memory/embeddings.rs` | CRUD for `idx_embedding` table | `upsert`, `find_similar`, `delete`, `count`, `SimilarHit` |
| `memory/store.rs` | Open / migrate views.db | `open`, `default_path` |
| `memory/session_start_recall.rs` | Existing-only bounded local recall preparation after RAW delivery and before the first provider prompt; stale/failed work is not retried from the prompt path and Incognito does not construct it | internal `start_session_recall_preload`, `SessionStartRecallPreload` |
| `memory/migrations/mod.rs` | Transactional schema migration chain, including v46 → v47 document provenance | (internal) |

## Schema

```sql
CREATE TABLE idx_embedding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_kind TEXT    NOT NULL,
    source_ref  TEXT    NOT NULL,
    model       TEXT    NOT NULL,
    embedding   BLOB    NOT NULL,   -- dim × 4 bytes, little-endian f32, L2-normalised
    dim         INTEGER NOT NULL,   -- used as filter in similarity queries
    created_at  INTEGER NOT NULL,   -- unix seconds
    UNIQUE (source_kind, source_ref)
);
```

Natural key is `(source_kind, source_ref)`. Re-ingesting the same file replaces the row.

## source_kind Values

| Value | Populated by |
|-------|-------------|
| `"image"` | `VisionExtractor` via CLIP ViT-B/32 |
| `"audio_segment"` | Reserved for future whisper-mel embeddings |
| `"video_frame"` | Reserved for future per-frame embeddings |
| `"pdf_page"` | Reserved for future text embeddings |
| `"asset"` | Fallback for `AssetKind::Other` |

## Data Flow

```
Embedding Vec<f32> (must be L2-normalised before call)
  → floats_to_blob: pack as little-endian f32 bytes
  → INSERT OR REPLACE INTO idx_embedding
  → rowid returned

Query Vec<f32> (must be L2-normalised)
  → SELECT rows WHERE dim = query.len() [AND source_kind = filter]
  → blob_to_floats: unpack each candidate
  → dot(query, candidate) = cosine similarity (both L2-normalised)
  → sort DESC, truncate to top_k
  → Vec<SimilarHit> { id, source_kind, source_ref, model, similarity, created_at }
```

## Correctness Invariants

- Embeddings MUST be L2-normalised at insert time. `debug_assert!(is_unit_norm)` guards
  both `upsert` and `find_similar` in debug builds. Tolerance is ±5% to cover f32 round-off
  from CLIP / Whisper preprocessing.
- Zero vectors (`norm ≈ 0`) pass the norm check and can be stored; they score 0 similarity
  against any query.
- Dim mismatch between stored rows and query is silently skipped (SQL `WHERE dim = ?1`
  pre-filters; the in-memory `blob_to_floats` rejects unexpected lengths with a WARN log).

## Related Areas

- `providers/clip_engine.rs` — produces the 512-dim vectors stored here
- `cli/ingest.rs` — calls `embeddings::upsert` after extraction
- `cli/recall.rs` — calls `embeddings::find_similar` for `--similar-to` / `--similar-to-text`
- `wal/events.rs` — `0x2D EMBED_PERSISTED` records when a row lands

## Ctx document provenance

`memory/ctx.rs` remains the owner of source replacement and its two FTS
projections. `memory/document_provenance.rs` validates the bounded metadata
contract shared by ingestion and search. Schema v47 adds eight nullable columns
to the existing `sources` row; v46 migration preserves historical rows with all
eight values NULL.

An `IndexRequest.document_provenance` must match the complete extracted UTF-8
text before replacement begins. The source insert, provenance, FTS writes, and
chunk count commit together. A replacement without provenance clears the prior
values. Failed replacements retain the old source and search data.
`CtxHit.source_document_provenance` exposes the same source metadata for BM25,
trigram, and fuzzy hits. Mixed-NULL or invalid persisted values return an error
instead of silently appearing as unbound legacy data.

`purge(Source(label))` returns the actual committed source-removal count:
one for an existing source, zero for a missing or already removed source.
Removing the source removes its provenance with the same transaction; the B7
`document_claims` ledger is a separate owner and is unchanged by this slice.

Schema v48 repairs historical fuzzy vocabulary drift once by rebuilding it from
canonical `chunks.content` only. Replacement and source/category purge subtract
each old chunk's distinct eligible terms before deleting source/FTS rows, within
the same transaction. All-purge clears the vocabulary too. Repeated indexing
therefore preserves per-chunk counts. The vocabulary is a derived index, not a
second document authority; missing, invalid or exhausted counts abort a mutation.
The migration requires its caller's transaction and rolls back both vocabulary
and version on failure. Normal edits read only affected source chunks.

## Explicit logical documents (schema v50)

ctx/logical.rs owns explicit registration, content revision and metadata rename
inside the existing ctx transaction. ctx/logical_request.rs validates the strict,
bounded request and hashes its canonical semantics. A logical ID points to one
current physical source. Event receipts retain historical results; a replay says
whether that event is still current. Rename preserves content/revision and updates
both FTS paths. It changes indexed metadata, never a file on disk.

Revision requires the expected source ID, revision and current event. Ordinary
label-based replacement refuses a source bound to a logical ID. Successful purge
removes the owner and its receipts with the source and advances the global request
epoch. Empty purge leaves the epoch unchanged. An old request therefore cannot
recreate a removed document. The epoch is a stale-request guard, not permission.

cli/ctx.rs exposes request-file/stdin, status and epoch modes. Request decoding and
status-ID validation precede database opening. Legacy stores remain unbound during
v49-to-v50 migration. [CLI usage](../CTX_LOGICAL_DOCUMENTS.md) describes the wire
format and replay boundaries. The B7 claim ledger and provider consent owners are
unchanged.
