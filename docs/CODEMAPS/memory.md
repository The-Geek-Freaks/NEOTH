# Memory Codemap — Embedding Store

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/memory/embeddings.rs`, `SRC/neothd/src/memory/store.rs`

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
| `memory/migrations/mod.rs` | Schema migration chain v3 → v6 | (internal) |

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
