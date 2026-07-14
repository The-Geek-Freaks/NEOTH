# CLI Codemap — Ingest + Models

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/cli/ingest.rs`, `SRC/neothd/src/cli/models.rs`

## cli/ingest.rs

`neoth ingest <path>` — multimodal asset ingest pipeline. Detect kind → extract → persist
embedding → emit WAL audit events → print report.

### Command surface

```
neoth ingest <PATH>
  [--db PATH]           override views.db path
  [--wal-segment PATH]  override WAL segment path
  [--no-persist]        skip embedding persistence (inspection / tests)
  [--no-audit]          skip WAL audit events (batch reprocessing)
  [--output table|json] output format (inherited from global --output)
```

### File kind detection (by extension, case-insensitive)

| Extensions | AssetKind |
|-----------|-----------|
| `.pdf` | Pdf |
| `.png .jpg .jpeg .webp .gif` | Image |
| `.wav .mp3 .flac .ogg .m4a` | Audio |
| `.mp4 .mov .mkv .webm` | Video |

### Pipeline

```
detect_kind(path)
  → Asset::Path { kind, mime, path }
  → route_to_first_match(backends, asset)   [pdf, vision, audio, video]
  → Extraction { text, metadata { embedding?, extractor, embed_status } }

if !no_persist && metadata.embedding present:
  → embeddings::upsert(conn, source_kind, source_ref, model, embedding)

if !no_audit && no live daemon:
  → WAL writer (one-shot spawn)
  → append 0x2C INGEST_EXTRACTED
  → append 0x2D EMBED_PERSISTED (only if embedding landed)

print IngestReport { path, kind, text_bytes, preview, embed_status, embed_persisted, metadata }
```

### WAL concurrency contract

`neoth ingest` emits audit events only when no `neoth serve` daemon owns the WAL segment
(checked via pidfile). If the daemon is running, audit emission is skipped with a WARN log;
the extraction report still prints. This avoids interleaved frames between two concurrent
O_APPEND writers.

### Source ref

Canonical source_ref is `fs::canonicalize(path)` (absolute, resolved symlinks). Falls back
to the display path on canonicalization error.

## cli/models.rs

`neoth models list|pull|prune` — manage `~/.neoth/models/` cache.

### Command surface

```
neoth models list
neoth models pull <clip|whisper> [--repo HF_REPO]
neoth models prune <clip|whisper>
```

### Known model catalogue

| Name | Description | Default repo | Required files |
|------|-------------|-------------|----------------|
| `clip` | CLIP ViT-B/32 image + text embeddings | `openai/clip-vit-base-patch32` | config.json, model.safetensors, tokenizer.json |
| `whisper` | Whisper large-v3-turbo transcription | `openai/whisper-large-v3-turbo` | config.json, tokenizer.json, model.safetensors |

`qwen` is intentionally absent — local Qwen has its own hardware-sizing onboarding flow in
`cli/init.rs::step5b_inference_topology`.

### pull behaviour

Delegates to `ClipEngine::new(repo)` / `WhisperEngine::new(repo)` which call
`ensure_artifacts()`. If all three required files are already present the HF Hub API is not
called. 15-minute per-file download timeout.

### prune behaviour

`std::fs::remove_dir_all` on the engine's `default_cache_dir`. No-op when the directory is
already absent.

## Related Areas

- `providers/clip_engine.rs` / `providers/whisper.rs` — the engines whose cache `models` manages
- `memory/embeddings.rs` — where extracted embeddings land
- `cli/doctor.rs` — `check_model_caches()` reports cached vs missing for both models
- `wal/events.rs` — `0x2C INGEST_EXTRACTED`, `0x2D EMBED_PERSISTED`
